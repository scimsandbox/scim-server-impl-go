package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
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
	if cfg.Server.CursorSecret != "" {
		scim.SetCursorSecret(cfg.Server.CursorSecret)
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
			hasExplicitBaseURL := false
			if lookupEnv != nil {
				if v, ok := lookupEnv("GO_SERVER_BASE_URL"); ok && strings.TrimSpace(v) != "" {
					hasExplicitBaseURL = true
				}
			}
			if !hasExplicitBaseURL && strings.TrimSpace(os.Getenv("GO_SERVER_BASE_URL")) != "" {
				hasExplicitBaseURL = true
			}
			if !hasExplicitBaseURL && (cfg.Server.BaseURL == "" || cfg.Server.BaseURL == "http://localhost:8080") {
				cfg.Server.BaseURL = ""
				cfg.Server.BaseURL = serverBaseURL(cfg)
			}
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

	if err := ensureCursorSecret(context.Background(), cfg, lookupEnv); err != nil {
		logger.Error("failed to initialize cursor secret", logging.Error(err))
		return err
	}

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
	asyncEventRepo := repository.NewAsyncEventRepository()

	// Services
	cleanupService := service.NewWorkspaceCleanupService(workspaceRepo, logger)

	// Handlers
	userHandler := handler.NewUserHandler(userRepo, membershipRepo, workspaceRepo, asyncEventRepo)
	groupHandler := handler.NewGroupHandler(groupRepo, membershipRepo, userRepo, workspaceRepo, asyncEventRepo)
	asyncEventHandler := handler.NewAsyncEventHandler(asyncEventRepo)
	bulkHandler := handler.NewBulkHandler(userHandler, groupHandler)
	discoveryHandler := handler.NewDiscoveryHandler(userHandler, groupHandler)
	meHandler := handler.NewMeHandler()

	apiRouter := chi.NewRouter()
	apiRouter.NotFound(func(w http.ResponseWriter, r *http.Request) {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Requested SCIM endpoint or protocol version not found"))
	})
	apiRouter.MethodNotAllowed(handler.MethodNotAllowed)
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
		const usersCollectionPath = "/Users"
		r.Post(usersCollectionPath, userHandler.CreateUser)
		r.Get(usersCollectionPath, userHandler.ListUsers)
		r.Put(usersCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))
		r.Patch(usersCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))
		r.Delete(usersCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))

		const usersPath = "/Users/{id}"
		r.Get(usersPath, userHandler.GetUser)
		r.Put(usersPath, userHandler.ReplaceUser)
		r.Patch(usersPath, userHandler.PatchUser)
		r.Delete(usersPath, userHandler.DeleteUser)
		r.Post(usersPath, handler.MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		const usersSearchPath = "/Users/.search"
		r.Post(usersSearchPath, userHandler.SearchUsers)
		r.Get(usersSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Put(usersSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Patch(usersSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Delete(usersSearchPath, handler.MethodNotAllowedWithAllow("POST"))

		const groupsCollectionPath = "/Groups"
		r.Post(groupsCollectionPath, groupHandler.CreateGroup)
		r.Get(groupsCollectionPath, groupHandler.ListGroups)
		r.Put(groupsCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))
		r.Patch(groupsCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))
		r.Delete(groupsCollectionPath, handler.MethodNotAllowedWithAllow("GET, POST"))

		const groupsPath = "/Groups/{id}"
		r.Get(groupsPath, groupHandler.GetGroup)
		r.Put(groupsPath, groupHandler.ReplaceGroup)
		r.Patch(groupsPath, groupHandler.PatchGroup)
		r.Delete(groupsPath, groupHandler.DeleteGroup)
		r.Post(groupsPath, handler.MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		const groupsSearchPath = "/Groups/.search"
		r.Post(groupsSearchPath, groupHandler.SearchGroups)
		r.Get(groupsSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Put(groupsSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Patch(groupsSearchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Delete(groupsSearchPath, handler.MethodNotAllowedWithAllow("POST"))

		const eventsPath = "/Events/{txnId}"
		r.Get(eventsPath, asyncEventHandler.GetEvent)
		r.Post(eventsPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(eventsPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(eventsPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(eventsPath, handler.MethodNotAllowedWithAllow("GET"))

		r.Get("/", discoveryHandler.RootSearch)
		r.Post("/", handler.MethodNotAllowedWithAllow("GET"))
		r.Put("/", handler.MethodNotAllowedWithAllow("GET"))
		r.Patch("/", handler.MethodNotAllowedWithAllow("GET"))
		r.Delete("/", handler.MethodNotAllowedWithAllow("GET"))

		const bulkPath = "/Bulk"
		r.Post(bulkPath, bulkHandler.ProcessBulk)
		r.Get(bulkPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Put(bulkPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Patch(bulkPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Delete(bulkPath, handler.MethodNotAllowedWithAllow("POST"))

		const searchPath = "/.search"
		r.Post(searchPath, discoveryHandler.RootSearch)
		r.Get(searchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Put(searchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Patch(searchPath, handler.MethodNotAllowedWithAllow("POST"))
		r.Delete(searchPath, handler.MethodNotAllowedWithAllow("POST"))

		const serviceProviderConfigPath = "/ServiceProviderConfig"
		r.Get(serviceProviderConfigPath, discoveryHandler.GetServiceProviderConfig)
		r.Post(serviceProviderConfigPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(serviceProviderConfigPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(serviceProviderConfigPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(serviceProviderConfigPath, handler.MethodNotAllowedWithAllow("GET"))

		const schemasPath = "/Schemas"
		r.Get(schemasPath, discoveryHandler.GetSchemas)
		r.Post(schemasPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(schemasPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(schemasPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(schemasPath, handler.MethodNotAllowedWithAllow("GET"))

		const schemaByIDPath = "/Schemas/{id}"
		r.Get(schemaByIDPath, discoveryHandler.GetSchemaByID)
		r.Post(schemaByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(schemaByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(schemaByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(schemaByIDPath, handler.MethodNotAllowedWithAllow("GET"))

		const resourceTypesPath = "/ResourceTypes"
		r.Get(resourceTypesPath, discoveryHandler.GetResourceTypes)
		r.Post(resourceTypesPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(resourceTypesPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(resourceTypesPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(resourceTypesPath, handler.MethodNotAllowedWithAllow("GET"))

		const resourceTypeByIDPath = "/ResourceTypes/{id}"
		r.Get(resourceTypeByIDPath, discoveryHandler.GetResourceTypeByID)
		r.Post(resourceTypeByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Put(resourceTypeByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Patch(resourceTypeByIDPath, handler.MethodNotAllowedWithAllow("GET"))
		r.Delete(resourceTypeByIDPath, handler.MethodNotAllowedWithAllow("GET"))

		r.HandleFunc("/Me", meHandler.Handle)

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Resource not found"))
		})
		r.MethodNotAllowed(handler.MethodNotAllowed)
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

	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()

	var cleanupWg sync.WaitGroup

	// Workspace cleanup scheduler
	if cfg.Cleanup.Enabled {
		cleanupWg.Add(1)
		go func() {
			defer cleanupWg.Done()
			cleanupService.Start(serverCtx, cfg.Cleanup.Interval, cfg.Cleanup.StaleAfter)
		}()
	}

	// Request log cleanup scheduler
	requestLogsEnabled := cfg.Cleanup.Enabled && (cfg.Cleanup.RequestLogs.Enabled != nil && *cfg.Cleanup.RequestLogs.Enabled)
	requestLogCleanupService := service.NewRequestLogCleanupService(
		requestLogRepo,
		logger,
		requestLogsEnabled,
		cfg.Cleanup.RequestLogs.Interval,
		cfg.Cleanup.RequestLogs.MaxCount,
	)
	if requestLogsEnabled {
		cleanupWg.Add(1)
		go func() {
			defer cleanupWg.Done()
			requestLogCleanupService.Start(serverCtx)
		}()
	}

	// Async event cleanup scheduler
	asyncEventsEnabled := cfg.Cleanup.Enabled && (cfg.Cleanup.AsyncEvents.Enabled != nil && *cfg.Cleanup.AsyncEvents.Enabled)
	asyncEventCleanupService := service.NewAsyncEventCleanupService(
		asyncEventRepo,
		logger,
		asyncEventsEnabled,
		cfg.Cleanup.AsyncEvents.Interval,
		cfg.Cleanup.AsyncEvents.MaxCount,
		cfg.Cleanup.AsyncEvents.StalePendingAfter,
		serverBaseURL(cfg),
	)
	if asyncEventsEnabled {
		cleanupWg.Add(1)
		go func() {
			defer cleanupWg.Done()
			asyncEventCleanupService.Start(serverCtx)
		}()
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

	cancelServer()
	cleanupWg.Wait()

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

func ensureCursorSecret(ctx context.Context, cfg Config, lookupEnv LookupEnvFunc) error {
	secret := strings.TrimSpace(cfg.Server.CursorSecret)
	if secret == "" && lookupEnv != nil {
		if v, ok := lookupEnv("SCIM_CURSOR_SECRET"); ok {
			secret = strings.TrimSpace(v)
		}
	}
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("SCIM_CURSOR_SECRET"))
	}
	if secret != "" {
		scim.SetCursorSecret(secret)
		return nil
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate cursor secret: %w", err)
	}
	candidate := hex.EncodeToString(raw)

	const createTableSQL = `
CREATE TABLE IF NOT EXISTS scim_system_secrets (
    secret_key VARCHAR(64) PRIMARY KEY,
    secret_value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
)`
	if _, err := jdbc.ExecContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("create scim_system_secrets table: %w", err)
	}

	const insertSQL = `
INSERT INTO scim_system_secrets (secret_key, secret_value)
VALUES ('cursor_hmac_secret', $1)
ON CONFLICT (secret_key) DO NOTHING`
	if _, err := jdbc.ExecContext(ctx, insertSQL, candidate); err != nil {
		return fmt.Errorf("insert cursor secret: %w", err)
	}

	var stored string
	if err := jdbc.QueryRowContext(ctx,
		`SELECT secret_value FROM scim_system_secrets WHERE secret_key = 'cursor_hmac_secret'`,
	).Scan(&stored); err != nil {
		return fmt.Errorf("load cursor secret: %w", err)
	}
	if strings.TrimSpace(stored) == "" {
		return fmt.Errorf("empty cursor secret in scim_system_secrets")
	}

	scim.SetCursorSecret(stored)
	return nil
}
