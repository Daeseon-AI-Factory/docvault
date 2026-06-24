# DalkkakAI 아키텍처 셋업 — `ㅇㅇ`

너는 이 프로젝트의 **아키텍처 매니페스트를 작성**한다. DalkkakAI 엔진이 코드를 이미 스캔했고(아래 인벤토리 = 사실), 너는 **의미(이름·요약·런타임 플로우)** 만 채우면 된다.

- 프로젝트 루트: `/Users/daeseonyoo/Documents/GitHub/ai-product/docvault`
- 규모: 92 파일 · 373 심볼 · 현재 자동그룹 17개 (커플링/존 기반 임시명 — 네가 사람이 읽을 이름으로 바꿔라)
- 현재 선언 커버리지: **100.0%** (목표: assign 규칙으로 90%+ 덮기)


## 산출물 (정확히 2개 파일)

### 1) `/Users/daeseonyoo/Documents/GitHub/ai-product/docvault/.dalkkak/arch.json`
아래 스키마 **그대로**. 핵심은 `assign`: 경로 prefix → 사람이 읽는 컴포넌트명. 트리를 최대한 덮어라(미분류 최소화). 주석 없는 중요 파일엔 `summaries` 한 줄.
```json
{
  "assign":   [{"prefix": "src/auth/", "domain": "Auth"}],      // longest-prefix → 컴포넌트명. 트리를 최대한 덮어라(=커버리지↑)
  "files":    {"src/weird/x.ts": "Auth"},                        // 예외 파일만 개별 지정(선택)
  "layers":   {"Auth": "⚙ Backend", "Login UI": "🖥 Renderer"},  // 컴포넌트 → 런타임 컨테이너
  "summaries":     {"src/auth/jwt.ts": "JWT 발급·검증"},          // 주석 없는 파일에 한 줄(코드 기반, 지어내지 말 것)
  "sym_summaries": {"src/auth/jwt.ts": {"sign": "토큰 서명"}},    // 핵심 파일의 주요 심볼만(선택)
  "summary_basis": {"src/auth/jwt.ts": "<생략가능>"}              // staleness용 — 생략해도 됨
}
```

### 2) `/Users/daeseonyoo/Documents/GitHub/ai-product/docvault/.dalkkak/flow.json`
**시스템이 런타임에 어떻게 도는지** — 정적 구조가 아니라 흐름. 아래 허브 파일/진입점부터 코드를 따라 읽고, 계층(layers) + 노드 + 주요 end-to-end 플로우(steps)를 작성.
```json
{
  "title":  "PROJECT — 시스템 플로우",
  "layers": ["사용자", "UI", "API 경계", "코어", "스토어", "외부"],   // 위→아래 런타임 계층(이 프로젝트에 맞게)
  "nodes":  [{"id":"ui","label":"로그인 화면","layer":"UI","kind":"component","note":"한 줄 설명"}],
              // kind: actor | component | boundary | datastore | external
  "flows":  [{"name":"로그인", "steps":["사용자: 이메일 입력", "UI → API: POST /login", "API: JWT 발급", "API → UI: 토큰 반환"]}]
              // steps = "주체: 행동" 또는 "A → B: 행동" — 실제 코드의 호출 경로를 따라가서 작성
}
```

## 규칙 (어기지 말 것)
1. **지어내지 마라.** 요약·플로우는 실제 코드에서 읽은 것만. 불확실하면 노드 note에 `(추정)` 표기.
2. 컴포넌트명은 **도메인 의미**로 (파일명/폴더명 복붙 금지). 예: `«index.tsx»` → `대시보드 홈`.
3. `assign` prefix는 **겹치면 더 긴 게 우선** — 큰 묶음 먼저, 예외는 더 깊은 prefix나 `files`로.
4. flow `steps`는 `"주체: 행동"` 또는 `"A → B: 행동"` 형식. 8±4 스텝 권장.
5. 다 쓰면 두 파일을 **유효한 JSON으로 저장만** 하면 된다(다른 출력 불필요).

## 흐름 추적용 허브 파일 (의존 많이 받는 = 진입점/중심)
- (엣지 없음 — 모듈단위 언어일 수 있음)

## 스캔된 파일 인벤토리 (사실 — 이름만 붙여라)

### 컨테이너(런타임): ☁ 서버 (Cloud Backend)
- 현재 자동그룹 「웹 UI·라우터」 (14 파일):
    - `internal/web/render.go` · sym: isMachineUser, selectedUser, formatBytes, newTemplateCache, renderPage, renderStandalone
    - `internal/web/csrf.go` · sym: CSRFMiddleware, generateCSRFToken, validateCSRFToken, CSRFToken
    - `internal/web/ratelimit_test.go` · sym: TestRateLimiterLocksAfterMaxAttempts, TestRateLimiterClearsOnSuccess, TestRateLimiterDifferentIPs, TestRateLimiterRemainingAttempts, TestRateLimiterUnlockedIP
    - `internal/web/sse.go` · sym: NewSSEHub, int
    - `internal/web/ratelimit.go` · sym: NewLoginRateLimiter, bool, bool, int, ExtractIP, LoginRateLimitMiddleware
    - `internal/web/router_test.go` · sym: TestAllRoutesRegistered, TestFormActionsHaveHandlers, TestStaticFilesServed, TestDownloadDocsServedFromEmbeddedStaticFiles
    - `internal/web/csv_test.go` · sym: TestCSVSafeFieldPreventsSpreadsheetFormulaInjection
    - `internal/web/pages.go` · sym: NewPageHandler, basePage, normalizeDefaultLang, demoLoginUsername, bool, string
    - `internal/web/csrf_test.go` · sym: TestCSRFMiddlewareBlocksWithoutToken, TestCSRFMiddlewareAllowsGET, TestCSRFMiddlewareAllowsMatchingToken, TestCSRFMiddlewareBlocksMismatchedToken, TestCSRFMiddlewareAcceptsHeader, TestCSRFMiddlewareIssuesCookie
    - `internal/web/forms.go` · sym: NewFormHandler, randomImportPassword, bool
    - `internal/web/sse_test.go` · sym: waitUntil, TestSSEHubBroadcast, TestSSEHubMultipleClients, TestSSEHubBroadcastTypes
    - `internal/web/render_test.go` · sym: TestTemplateCache, TestTemplatePagesRenderDifferentContent, TestLoginTemplateRenders, TestLoginTemplateDemoButtonIsConditional, TestFormatBytes
    - `internal/web/router.go` · sym: NewRouter, auditAuthAction
    - `internal/web/static/htmx.min.js`
- 현재 자동그룹 「인증·JWT·2FA」 (10 파일):
    - `internal/auth/handler.go` · sym: NewHandler
    - `internal/auth/totp.go` · sym: GenerateTOTPSecret, GenerateTOTPURI, ValidateTOTP, ValidateTOTPAt, GenerateTOTPCode, GenerateTOTPCodeAt
    - `internal/auth/middleware_test.go` · sym: TestMiddlewareBlocksNoToken, TestMiddlewareBlocksInvalidToken, TestMiddlewareAllowsValidToken, TestMiddlewareReadsCookie, TestRequireRoleBlocks, TestRequireRoleAllows
    - `internal/auth/token_refresh_test.go` · sym: TestTokenRefreshMiddlewareRefreshesExpiringToken, TestTokenRefreshMiddlewareSkipsFreshToken, TestTokenRefreshMiddlewareSkipsNoCookie
    - `internal/auth/jwt_test.go` · sym: TestJWTGenerateAndValidate, TestJWTInvalidToken, TestJWTWrongSecret, TestJWTRejectsWrongTokenType, TestJWTExpiry, TestJWTDifferentRoles
    - `internal/auth/secret.go` · sym: NewSecretProtector, IsProtectedSecret
    - `internal/auth/totp_test.go` · sym: TestGenerateTOTPSecret, TestGenerateTOTPURI, TestTOTPGenerateAndValidate, TestTOTPRejectsWrongCode, TestTOTPRejectsInvalidLength, TestTOTPSkewTolerance
    - `internal/auth/secret_test.go` · sym: TestSecretProtectorRoundTrip, TestSecretProtectorKeepsLegacyPlaintextReadable, TestSecretProtectorRejectsBadMasterKey
    - `internal/auth/middleware.go` · sym: UserFromContext, Middleware, RequireRole, WebMiddleware, TokenRefreshMiddleware, extractToken
    - `internal/auth/jwt.go` · sym: NewJWTService, string
- 현재 자동그룹 「엔드포인트 이벤트 수집」 (10 파일):
    - `internal/endpoint/handler.go` · sym: NewHandler, bool, error, endpointUsernameCandidate, isAutoAssignableEndpointUsername, autoEndpointEmail
    - `internal/endpoint/osquery_tls.go` · sym: generateNodeKey, writeNodeInvalid, writeJSONResponse
    - `internal/endpoint/disguise_test.go` · sym: bool, string, TestIsExtensionChangedWithChecker, TestIsExtensionChangedFallbackWithoutChecker, TestNormalizeOsqueryEventsWithDisguiseChecker
    - `internal/endpoint/osquery.go` · sym: NormalizeOsqueryEvents, NormalizeOsqueryEventsWithChecker, mapOsqueryAction, extractFileName, extractFilePath, extractProcessName
    - `internal/endpoint/clipboard_test.go` · sym: TestNormalizeClipboardEventCopy, TestNormalizeClipboardEventPaste, TestNormalizeClipboardEventBadTimestamp
    - `internal/endpoint/osquery_test.go` · sym: TestNormalizeOsqueryEvents, TestMapOsqueryAction, TestNormalizeOsqueryEventsEmptyBatch, TestNormalizeMessengerFileAccess, TestNormalizeUSBCopy, TestPathBaseHandlesWindowsAndPOSIXPaths
    - `internal/endpoint/model.go`
    - `internal/endpoint/handler_test.go` · sym: TestAgentEndpointsFailClosedWhenPSKIsMissing, TestAgentEndpointsRejectWrongPSKBeforeProcessing, TestEndpointUsernameCandidate, TestIsAutoAssignableEndpointUsername, TestAutoEndpointEmailIsStableAndInternal
    - `internal/endpoint/repository.go` · sym: NewRepository, error, error, error, error, error
    - `internal/endpoint/clipboard.go` · sym: NormalizeClipboardEvent
- 현재 자동그룹 「파일 금고(암호화 저장)」 (9 파일):
    - `internal/vault/handler.go` · sym: NewHandler, bool
    - `internal/vault/encryption.go` · sym: GenerateKey, GenerateNonce, chunkNonce, EncryptStream, DecryptStream
    - `internal/vault/encryption_test.go` · sym: TestGenerateKey, TestGenerateNonce, TestEncryptDecryptStream, TestEncryptDecryptStreamLarge, TestWrongKeyFails, TestWrongNonceFails
    - `internal/vault/keymanager_test.go` · sym: testMasterKey, TestNewKeyManager, TestGenerateFileKey, TestEncryptDecryptKey, TestDecryptKeyWithWrongNonce, TestEnvelopeEncryptionRoundTrip
    - `internal/vault/storage_test.go` · sym: TestStorageWriteRead, TestStoragePathStructure, TestStorageDirectoryCreation
    - `internal/vault/storage.go` · sym: NewStorage, string, error
    - `internal/vault/model.go`
    - `internal/vault/keymanager.go` · sym: NewKeyManager
    - `internal/vault/repository.go` · sym: NewRepository, error, error, error, error, error
- 현재 자동그룹 「감사 로그(해시체인)」 (8 파일):
    - `internal/audit/handler.go` · sym: NewHandler, csvSafe, formatNullableInt, parsePagination
    - `internal/audit/middleware_test.go` · sym: TestDeriveAction, TestDeriveActionCoversAllActions, TestStatusRecorderPreservesFlusherWhenUnderlyingSupportsIt
    - `internal/audit/export.go` · sym: ExportCSV
    - `internal/audit/csv_test.go` · sym: TestCSVSafePreventsSpreadsheetFormulaInjection
    - `internal/audit/export_test.go` · sym: TestExportCSV, TestExportCSVEmpty, TestExportCSVNilTargetID
    - `internal/audit/model.go`
    - `internal/audit/middleware.go` · sym: Middleware, deriveAction, extractTarget, targetTypeFromPath
    - `internal/audit/repository.go` · sym: NewRepository, error
- 현재 자동그룹 「경보 룰 엔진」 (6 파일):
    - `internal/alert/handler.go` · sym: NewHandler
    - `internal/alert/engine_test.go` · sym: TestMatchesEventType, TestMatchesCondition, TestMatchesProcessGroup
    - `internal/alert/notifier.go` · sym: NewNotifier, error, error
    - `internal/alert/engine.go` · sym: NewEngine, matchesEventType, matchesConditionWithConfig, matchesCondition, matchesProcessGroup, matchesProcessGroupWithConfig
    - `internal/alert/model.go`
    - `internal/alert/repository.go` · sym: NewRepository, error, error, error
- 현재 자동그룹 「AI 어시스턴트」 (5 파일):
    - `internal/agent/actions.go` · sym: nullableInt, randomPW, logAction, actionTools, Rollback
    - `internal/agent/agent.go` · sym: withActor, actorFromContext, NewEngine, bool, string, hasActionConfirmation  «기존주석: Package agent is an in-product AI assistant that answers questions about»
    - `internal/agent/agent_test.go` · sym: string, testEngine, TestMutatingToolRequiresServerConfirmation, TestMutatingToolRunsAfterPendingConfirmation, TestReadToolRunsWithoutConfirmation
    - `internal/agent/providers.go` · sym: NewProvider, string, string
    - `internal/agent/help.go` · sym: helpTools
- 현재 자동그룹 「사용자 관리」 (4 파일):
    - `internal/user/handler.go` · sym: NewHandler
    - `internal/user/model_test.go` · sym: TestHashPassword, TestCheckPassword, TestRoleConstants
    - `internal/user/model.go` · sym: HashPassword, CheckPassword
    - `internal/user/repository.go` · sym: NewRepository, error, error, error
- 현재 자동그룹 「서버 부트스트랩」 (3 파일):
    - `cmd/server/seed.go` · sym: seedAdmin, truthy, seedAlertRules, seedDemoData, randomPassword
    - `cmd/server/migrate.go` · sym: runMigrations
    - `cmd/server/main.go` · sym: error, error, main, runMigrateCmd, runSeedCmd, run
- 현재 자동그룹 「폴더·권한」 (3 파일):
    - `internal/folder/handler.go` · sym: NewHandler, bool
    - `internal/folder/model.go`
    - `internal/folder/repository.go` · sym: NewRepository, error, error, error, error, error
- 현재 자동그룹 「AI 활동 요약」 (3 파일):
    - `internal/insight/handler.go` · sym: NewHandler
    - `internal/insight/summarizer.go` · sym: NewSummarizer, bool  «기존주석: Package insight turns recent endpoint activity into a short natural-language»
    - `internal/insight/summarizer_test.go` · sym: TestNewSummarizerProviderDefaults, TestSummaryHandlerDisabled
- 현재 자동그룹 「DB·마이그레이션」 (2 파일):
    - `internal/database/db.go` · sym: NewPool
    - `internal/database/migrations.go`  «기존주석: go:embed migrations/*.sql»
- 현재 자동그룹 「행위 이상탐지(UEBA)」 (2 파일):
    - `internal/ueba/analyzer.go` · sym: NewAnalyzer, Baseline, int, error, scoreToLevel, contains
    - `internal/ueba/analyzer_test.go` · sym: TestScoreToLevel, TestContains, TestFileExt, TestAnomalyWeights, TestAfterHoursDetection, TestWeekendDetection
- 현재 자동그룹 「환경설정」 (2 파일):
    - `internal/config/config.go` · sym: Load, truthyEnv, validateSecrets
    - `internal/config/config_test.go` · sym: TestLoadRequiredFields, TestLoadDefaults, TestLoadDemoLoginConfig, TestLoadRejectsWeakSecrets
- 현재 자동그룹 「모니터링 설정」 (2 파일):
    - `internal/monitoring/handler.go` · sym: NewHandler, writeJSON
    - `internal/monitoring/config.go` · sym: NewRepository, bool, string, string, bool, string
- 현재 자동그룹 「파일 해시 추적」 (1 파일):
    - `internal/tracking/tracker.go` · sym: NewTracker, int64, error, error

### 컨테이너(런타임): 🖥 엔드포인트 에이전트 (감시 대상 PC)
- 현재 자동그룹 「클립보드 감시 에이전트」 (8 파일):
    - `cmd/clipagent/service_windows.go` · sym: platformMain, agentRunningMode, installService, uninstallService  «기존주석: go:build windows»
    - `cmd/clipagent/service_darwin.go` · sym: platformMain, agentRunningMode  «기존주석: go:build darwin»
    - `cmd/clipagent/clipboard_darwin.go` · sym: newClipboardMonitor, getUsername, getFrontmostApp, looksLikeFilePaths, clipboardProbe  «기존주석: go:build darwin»
    - `cmd/clipagent/clipboard_windows.go` · sym: newClipboardMonitor, getUsername, getClipboardSequence, getClipboardContent, getProcessNameFromWindow, getForegroundWindowTitle  «기존주석: go:build windows»
    - `cmd/clipagent/agent.go` · sym: runMonitor, sendHeartbeat, sendSelfTest, enqueue, enrollAgent, sendEventWithRetry
    - `cmd/clipagent/clipboard_other.go` · sym: getUsername, newClipboardMonitor, clipboardProbe  «기존주석: go:build !windows && !darwin»
    - `cmd/clipagent/service_other.go` · sym: platformMain, agentRunningMode  «기존주석: go:build !windows && !darwin»
    - `cmd/clipagent/main.go` · sym: main
