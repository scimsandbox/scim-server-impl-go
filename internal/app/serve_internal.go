package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scimsandbox/scim-server-impl-go/internal/handler"
	"github.com/scimsandbox/scim-server-impl-go/internal/httpapi"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
	"github.com/scimsandbox/scim-server-impl-go/internal/service"
)

func serve(stderr io.Writer, lookupEnv LookupEnvFunc) error {
	cfg, err := loadConfig(lookupEnv)
	if err != nil {
		return err
	}

	logger := setupLogger(cfg, stderr)
	localizer := setupLocalizer(cfg)
	defer logger.Flush()

	// Database — use existing pool-based approach (kept for backward compatibility
	// with existing repositories that take *pgxpool.Pool)
	// Workaround for Docker parsing: explicitly inject JDBC URL if provided
	if val := os.Getenv("SPRING_DATASOURCE_URL"); val != "" {
		cfg.Storage.DSN = val
	}
	if val := os.Getenv("SPRING_DATASOURCE_USERNAME"); val != "" {
		cfg.Storage.Username = val
	}
	if val := os.Getenv("SPRING_DATASOURCE_PASSWORD"); val != "" {
		cfg.Storage.Password = val
	}
	if val := os.Getenv("SERVER_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Server.Port = p
		}
	}

	dsn := resolveDSN(cfg)
	fmt.Printf("DEBUG: Resolved DSN=%q\n", dsn)

	err = jdbc.Init(context.Background(), jdbc.Config{
		DSN:               dsn,
		MaxConns:          cfg.Storage.MaxConns,
		MinConns:          cfg.Storage.MinConns,
		MaxConnIdleTime:   30 * time.Minute,
		MaxConnLifetime:   time.Hour,
		HealthCheckPeriod: time.Minute,
	})
	if err != nil {
		logger.Error("failed to connect to database", logging.Error(err))
		return err
	}
	defer jdbc.Close()

	logger.Info(localizer.Text(messages.KeyConfigurationLoaded),
		logging.String("dsn", resolveDSN(printableConfig(cfg))),
		logging.Int("port", cfg.Server.Port),
		logging.Int("management_port", managementPort(cfg)),
	)

	// Repositories (jdbc-aware)
	userRepo := repository.NewUserRepository()
	groupRepo := repository.NewGroupRepository()
	membershipRepo := repository.NewMembershipRepository()
	workspaceRepo := repository.NewWorkspaceRepository()
	tokenRepo := repository.NewTokenRepository()
	requestLogRepo := repository.NewRequestLogRepository()

	// Services
	cleanupService := service.NewWorkspaceCleanupService(workspaceRepo, logger)

	// Handlers
	userHandler := handler.NewUserHandler(userRepo, membershipRepo, workspaceRepo)
	groupHandler := handler.NewGroupHandler(groupRepo, membershipRepo, userRepo, workspaceRepo)
	bulkHandler := handler.NewBulkHandler(userHandler, groupHandler)
	discoveryHandler := handler.NewDiscoveryHandler()
	meHandler := handler.NewMeHandler()

	apiRouter := chi.NewRouter()
	managementRouter := chi.NewRouter()
	managementRouter.Route("/actuator", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP"}`))
		})
	})
	managementRouter.Handle("/metrics", promhttp.Handler())

	// SCIM routes
	registerScimEndpoints := func(r chi.Router) {
		r.Post("/Users", userHandler.CreateUser)
		r.Get("/Users", userHandler.ListUsers)
		const usersPath = "/Users/{id}"
		r.Get(usersPath, userHandler.GetUser)
		r.Put(usersPath, userHandler.ReplaceUser)
		r.Patch(usersPath, userHandler.PatchUser)
		r.Delete(usersPath, userHandler.DeleteUser)
		r.Post("/Users/.search", userHandler.SearchUsers)

		r.Post("/Groups", groupHandler.CreateGroup)
		r.Get("/Groups", groupHandler.ListGroups)
		const groupsPath = "/Groups/{id}"
		r.Get(groupsPath, groupHandler.GetGroup)
		r.Put(groupsPath, groupHandler.ReplaceGroup)
		r.Patch(groupsPath, groupHandler.PatchGroup)
		r.Delete(groupsPath, groupHandler.DeleteGroup)
		r.Post("/Groups/.search", groupHandler.SearchGroups)

		r.Post("/Bulk", bulkHandler.ProcessBulk)

		const serviceProviderConfigPath = "/ServiceProviderConfig"
		r.Get(serviceProviderConfigPath, discoveryHandler.GetServiceProviderConfig)
		r.Post(serviceProviderConfigPath, handler.MethodNotAllowed)
		r.Put(serviceProviderConfigPath, handler.MethodNotAllowed)
		r.Patch(serviceProviderConfigPath, handler.MethodNotAllowed)
		r.Delete(serviceProviderConfigPath, handler.MethodNotAllowed)

		const schemasPath = "/Schemas"
		r.Get(schemasPath, discoveryHandler.GetSchemas)
		const schemaByIDPath = "/Schemas/{id}"
		r.Get(schemaByIDPath, discoveryHandler.GetSchemaByID)
		r.Post(schemasPath, handler.MethodNotAllowed)
		r.Put(schemaByIDPath, handler.MethodNotAllowed)
		r.Patch(schemaByIDPath, handler.MethodNotAllowed)
		r.Delete(schemaByIDPath, handler.MethodNotAllowed)

		const resourceTypesPath = "/ResourceTypes"
		r.Get(resourceTypesPath, discoveryHandler.GetResourceTypes)
		const resourceTypeByIDPath = "/ResourceTypes/{id}"
		r.Get(resourceTypeByIDPath, discoveryHandler.GetResourceTypeByID)
		r.Post(resourceTypesPath, handler.MethodNotAllowed)
		r.Put(resourceTypeByIDPath, handler.MethodNotAllowed)
		r.Patch(resourceTypeByIDPath, handler.MethodNotAllowed)
		r.Delete(resourceTypeByIDPath, handler.MethodNotAllowed)

		r.HandleFunc("/Me", meHandler.Handle)

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Resource not found"))
		})
	}

	apiRouter.Route("/ws/{workspaceId}/scim/v2", func(r chi.Router) {
		r.Use(middleware.ExtractWorkspaceID)
		r.Use(middleware.BearerTokenAuth(tokenRepo, workspaceRepo))
		r.Use(middleware.RequestResponseLogging(requestLogRepo))

		registerScimEndpoints(r)

		r.Route("/{compat}", func(r chi.Router) {
			registerScimEndpoints(r)
		})
	})

	// Workspace cleanup scheduler
	if cfg.Cleanup.Enabled {
		go cleanupService.Start(context.Background(), cfg.Cleanup.Interval, cfg.Cleanup.StaleAfter)
	}

	apiHandler := httpapi.New(apiRouter, httpapi.Config{
		Logger:    logger,
		Localizer: localizer,
		RateLimit: cfg.RateLimit,
	})
	managementHandler := httpapi.New(managementRouter, httpapi.Config{Logger: logger, Localizer: localizer})

	apiAddr := ":" + strconv.Itoa(cfg.Server.Port)
	apiServer := &http.Server{
		Addr:              apiAddr,
		Handler:           apiHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}
	managementAddr := ":" + strconv.Itoa(managementPort(cfg))
	managementServer := &http.Server{
		Addr:              managementAddr,
		Handler:           managementHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(done)

	serverErrors := make(chan error, 2)

	startServer := func(name string, srv *http.Server) {
		go func() {
			logger.Info(localizer.Text(messages.KeyHTTPServerStarted),
				logging.String("listener", name),
				logging.String("addr", srv.Addr),
			)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrors <- fmt.Errorf("%s listener: %w", name, err)
			}
		}()
	}

	startServer("api", apiServer)
	startServer("management", managementServer)

	var runErr error
	select {
	case <-done:
		logger.Info(localizer.Text(messages.KeyHTTPServerStopped))
	case runErr = <-serverErrors:
		logger.Error("server error", logging.Error(runErr))
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	shutdownError := shutdownServers(ctx, managementServer, apiServer)
	if runErr != nil {
		if shutdownError != nil {
			return fmt.Errorf("%w: %v", runErr, shutdownError)
		}
		return runErr
	}

	return shutdownError
}

func shutdownServers(ctx context.Context, servers ...*http.Server) error {
	var shutdownError error
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed && shutdownError == nil {
			shutdownError = err
		}
	}
	return shutdownError
}
