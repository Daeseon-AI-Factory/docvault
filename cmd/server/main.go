package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/agent"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/alert"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/audit"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/config"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/database"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/folder"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/insight"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/monitoring"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/tracking"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/ueba"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/vault"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/web"
)

// uebaBridge adapts ueba.Analyzer to both endpoint.BehaviorAnalyzer and web.UEBARiskProvider.
type uebaBridge struct {
	analyzer *ueba.Analyzer
}

func (b *uebaBridge) GetTopRiskUsers(ctx context.Context, limit int) ([]web.UserRiskSummary, error) {
	users, err := b.analyzer.GetTopRiskUsers(ctx, limit)
	if err != nil {
		return nil, err
	}
	result := make([]web.UserRiskSummary, len(users))
	for i, u := range users {
		result[i] = web.UserRiskSummary{
			UserID: u.UserID, Username: u.Username, FullName: u.FullName,
			Score: u.Score, Level: u.Level,
		}
	}
	return result, nil
}

func (b *uebaBridge) AnalyzeEvent(ctx context.Context, evt endpoint.BehaviorEventContext) []endpoint.BehaviorRiskFactor {
	factors := b.analyzer.AnalyzeEvent(ctx, ueba.EventContext{
		UserID:      evt.UserID,
		EventType:   evt.EventType,
		FileName:    evt.FileName,
		FilePath:    evt.FilePath,
		ProcessName: evt.ProcessName,
		Hostname:    evt.Hostname,
		IPAddress:   evt.IPAddress,
		EventTime:   evt.EventTime,
	})
	result := make([]endpoint.BehaviorRiskFactor, len(factors))
	for i, f := range factors {
		result[i] = endpoint.BehaviorRiskFactor{Factor: f.Factor, Weight: f.Weight, Detail: f.Detail}
	}
	return result
}

// trackerBridge adapts tracking.Tracker to web.FileTrackerUI interface.
type trackerBridge struct {
	tracker *tracking.Tracker
}

func (b *trackerBridge) List(ctx context.Context) ([]web.TrackedFileView, error) {
	files, err := b.tracker.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]web.TrackedFileView, len(files))
	for i, f := range files {
		result[i] = web.TrackedFileView{
			ID: f.ID, OriginalName: f.OriginalName, SHA256Hash: f.SHA256Hash,
			Sensitivity: f.Sensitivity, Description: f.Description, IsActive: f.IsActive,
		}
	}
	return result, nil
}

func (b *trackerBridge) GetAllDetections(ctx context.Context, limit int) ([]web.DetectionView, error) {
	return b.convertDetections(b.tracker.GetAllDetections(ctx, limit))
}

func (b *trackerBridge) GetDetections(ctx context.Context, trackedFileID int64, limit int) ([]web.DetectionView, error) {
	return b.convertDetections(b.tracker.GetDetections(ctx, trackedFileID, limit))
}

func (b *trackerBridge) convertDetections(dets []tracking.Detection, err error) ([]web.DetectionView, error) {
	if err != nil {
		return nil, err
	}
	result := make([]web.DetectionView, len(dets))
	for i, d := range dets {
		result[i] = web.DetectionView{
			ID: d.ID, TrackedFileID: d.TrackedFileID, OriginalName: d.OriginalName,
			Sensitivity: d.Sensitivity, FoundName: d.FoundName, FoundPath: d.FoundPath,
			Hostname: d.Hostname, EventType: d.EventType, ProcessName: d.ProcessName,
			DetectedAt: d.DetectedAt,
		}
	}
	return result, nil
}

func (b *trackerBridge) Register(ctx context.Context, name, sha256, md5, sensitivity, description string, userID int64) error {
	return b.tracker.Register(ctx, name, sha256, md5, sensitivity, description, userID)
}

func (b *trackerBridge) Unregister(ctx context.Context, id int64) error {
	return b.tracker.Unregister(ctx, id)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	var err error
	switch cmd {
	case "serve":
		err = run(logger)
	case "migrate":
		err = runMigrateCmd(logger)
	case "seed":
		err = runSeedCmd(logger)
	default:
		fmt.Fprintf(os.Stderr, "Usage: docvault [serve|migrate|seed]\n")
		os.Exit(1)
	}

	if err != nil {
		logger.Error("command failed", "command", cmd, "error", err)
		os.Exit(1)
	}
}

func runMigrateCmd(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.DBUrl)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	return runMigrations(ctx, pool, logger)
}

func runSeedCmd(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.DBUrl)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	return seedAdmin(ctx, pool, logger)
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.DBUrl)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()
	logger.Info("connected to database")

	jwtSvc := auth.NewJWTService(cfg.JWTSecret)

	// Vault dependencies
	keyMgr, err := vault.NewKeyManager(cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("create key manager: %w", err)
	}
	totpProtector, err := auth.NewSecretProtector(cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("create totp secret protector: %w", err)
	}

	storage, err := vault.NewStorage(cfg.VaultPath)
	if err != nil {
		return fmt.Errorf("create vault storage: %w", err)
	}

	vaultRepo := vault.NewRepository(pool)

	// Folder dependencies
	folderRepo := folder.NewRepository(pool)
	folderHandler := folder.NewHandler(folderRepo, logger)
	vaultHandler := vault.NewHandler(vaultRepo, folderRepo, storage, keyMgr, logger)

	// User dependencies
	userRepo := user.NewRepository(pool)
	userHandler := user.NewHandler(userRepo, logger)

	// Audit dependencies
	auditRepo := audit.NewRepository(pool)
	auditHandler := audit.NewHandler(auditRepo, logger)

	// Alert dependencies (must be created before endpoint handler)
	alertRepo := alert.NewRepository(pool)
	alertNotifier := alert.NewNotifier(cfg.SlackWebhook)
	alertEngine := alert.NewEngine(alertRepo, alertNotifier, logger)
	alertHandler := alert.NewHandler(alertRepo, logger)

	// Monitoring config (DB-based, replaces all hardcoded process/extension lists)
	monCfgRepo := monitoring.NewRepository(pool)
	monHandler := monitoring.NewHandler(pool, monCfgRepo, logger)
	alertEngine.SetMonitoringConfig(monCfgRepo)

	// SSE hub for real-time dashboard updates
	sseHub := web.NewSSEHub(logger)

	// UEBA: User & Entity Behavior Analytics
	uebaAnalyzer := ueba.NewAnalyzer(pool, logger)

	// Endpoint dependencies (alert engine wired in for real-time evaluation)
	endpointRepo := endpoint.NewRepository(pool)
	endpointHandler := endpoint.NewHandler(endpointRepo, pool, cfg.OsqueryPSK, alertEngine, logger)
	endpointHandler.SetMonitoringConfig(monCfgRepo)
	endpointHandler.SetSSEHub(sseHub)
	bridge := &uebaBridge{analyzer: uebaAnalyzer}
	endpointHandler.SetBehaviorAnalyzer(bridge)

	// File tracking (hash-based)
	fileTracker := tracking.NewTracker(pool, logger)
	endpointHandler.SetFileTracker(fileTracker)
	trackerBridge := &trackerBridge{tracker: fileTracker}

	// AI summary bot (optional — disabled unless DOCVAULT_ANTHROPIC_API_KEY is set)
	summarizer := insight.NewSummarizer(pool, cfg.AnthropicAPIKey, cfg.GeminiAPIKey, cfg.AIModel, logger)
	insightHandler := insight.NewHandler(summarizer, logger)
	if summarizer.Enabled() {
		logger.Info("AI summary enabled", "model", cfg.AIModel)
	}

	// AI assistant: tool-use agent over live data (same keys as the summary bot).
	agentProvider := agent.NewProvider(cfg.OpenAIAPIKey, cfg.GeminiAPIKey, cfg.AIProvider, cfg.AIModel)
	agentHandler := agent.NewHandler(agent.NewEngine(pool, agentProvider, logger), logger)
	if agentProvider != nil {
		logger.Info("AI assistant enabled", "provider", agentProvider.Name())
	}

	// Page handler (HTML templates)
	pageHandler, err := web.NewPageHandler(web.PageHandlerDeps{
		DB:                pool,
		JWTSvc:            jwtSvc,
		VaultRepo:         vaultRepo,
		FolderRepo:        folderRepo,
		UserRepo:          userRepo,
		AuditRepo:         auditRepo,
		EndpointRepo:      endpointRepo,
		AlertRepo:         alertRepo,
		MonitorHandler:    monHandler,
		UEBAAnalyzer:      bridge,
		FileTracker:       trackerBridge,
		PSKConfigured:     cfg.OsqueryPSK != "",
		AgentPSK:          cfg.OsqueryPSK,
		TOTPProtector:     totpProtector,
		Logger:            logger,
		DefaultLang:       cfg.DefaultLang,
		InstanceLabel:     cfg.InstanceLabel,
		DemoLoginEnabled:  cfg.DemoLoginEnabled,
		DemoLoginUsername: cfg.DemoLoginUsername,
	})
	if err != nil {
		return fmt.Errorf("create page handler: %w", err)
	}

	formHandler := web.NewFormHandler(web.FormHandlerDeps{
		VaultRepo:    vaultRepo,
		VaultStorage: storage,
		KeyManager:   keyMgr,
		FolderRepo:   folderRepo,
		UserRepo:     userRepo,
		AlertRepo:    alertRepo,
		EndpointRepo: endpointRepo,
		Logger:       logger,
	})

	router := web.NewRouter(web.RouterDeps{
		DB:              pool,
		JWTSvc:          jwtSvc,
		VaultHandler:    vaultHandler,
		FolderHandler:   folderHandler,
		UserHandler:     userHandler,
		AuditRepo:       auditRepo,
		AuditHandler:    auditHandler,
		EndpointHandler: endpointHandler,
		AlertHandler:    alertHandler,
		MonitorHandler:  monHandler,
		PageHandler:     pageHandler,
		FormHandler:     formHandler,
		SSEHub:          sseHub,
		InsightHandler:  insightHandler,
		AgentHandler:    agentHandler,
		TOTPProtector:   totpProtector,
		Logger:          logger,
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // disabled for SSE long-lived connections
		IdleTimeout:  120 * time.Second,
	}

	// UEBA baseline recalculation scheduler (daily at 2:00 AM).
	// Tied to a cancellable context so it stops cleanly on shutdown instead of
	// leaking a goroutine that blocks clean process termination.
	schedCtx, schedCancel := context.WithCancel(context.Background())
	defer schedCancel()
	go func() {
		if err := uebaAnalyzer.RecalculateBaselines(schedCtx); err != nil {
			logger.Error("initial baseline calculation", "error", err)
		}
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 2, 0, 0, 0, now.Location())
			timer := time.NewTimer(time.Until(next))
			select {
			case <-schedCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if err := uebaAnalyzer.RecalculateBaselines(schedCtx); err != nil {
				logger.Error("scheduled baseline calculation", "error", err)
			}
		}
	}()

	// Graceful shutdown
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("listen: %w", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("server stopped")
	return nil
}
