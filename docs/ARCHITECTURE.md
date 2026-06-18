# Architecture

DocVault는 단일 서버에 모든 컴포넌트가 모인 구조다. 사용자 PC에 두 종류의 에이전트(osquery, 클립보드 에이전트)가 깔리고, 이들이 HTTPS로 서버에 이벤트를 POST한다. 관리자는 브라우저로 같은 서버의 웹 UI에 접속해 이벤트와 감사 로그를 조회한다.

## 컴포넌트 토폴로지

```
[사용자 PC들]                            [서버 1대]                      [관리자]

osquery daemon         ──HTTPS POST──→  /api/events/osquery
                                              │
클립보드 에이전트(Go)   ──HTTPS POST──→  /api/events/clipboard
클립보드 에이전트(Go)   ──HTTPS POST──→  /api/heartbeat
                                              │
                                              ▼
                                       PostgreSQL 16
                                       ├ endpoint_events   (해시 체인 트리거)
                                       ├ audit_logs        (해시 체인 트리거)
                                       ├ files, file_versions
                                       ├ folders, folder_permissions
                                       ├ user_behavior_baselines
                                       ├ anomaly_events, risk_scores
                                       └ alerts, alert_rules

관리자 브라우저  ─────────HTTPS────────→ Go HTTP 서버 (chi)
                                       ├ JWT 인증 미들웨어
                                       ├ 감사 로깅 미들웨어 (cross-cutting)
                                       ├ CSRF / 레이트리밋 미들웨어
                                       └ 핸들러 → 리포지토리 → DB
                                              │
                                              ▼
                                       htmx 프래그먼트 / Go 템플릿

                                       백그라운드 goroutine:
                                       ├ 알림 엔진 (룰 매칭 → Slack)
                                       ├ 이상 행위 분석기 (이벤트별 룰 평가)
                                       └ 베이스라인 재계산 (매일 02:00 cron)

디스크: /vault/{file_id}/{version_id}.enc   — 암호화된 파일 블롭
```

배포 시 nginx가 TLS 종료와 리버스 프록시를 담당하고, 같은 호스트의 Go 서버(`localhost:8080`)로 전달한다.

## 핵심 데이터 흐름

### 1. 엔드포인트 이벤트 수신

```
osquery (Windows PC)
  scheduled query "find files written in last minute"
  ↓
  HTTPS POST /api/events/osquery (배치, 평균 ~50 이벤트)
  ↓
endpoint.HandleOsqueryEvents
  └→ 이벤트 포맷 normalize (osquery 스키마 → endpoint_events 스키마)
  └→ hostname으로 user_id 매핑 (hostname_mapping 테이블)
  └→ INSERT INTO endpoint_events (10개 컬럼)
       ↓ DB 트리거
       └→ 마지막 행의 row_hash 읽기
       └→ NEW.prev_hash := 그 값
       └→ NEW.row_hash := SHA256(prev_hash || user_id || hostname || event_type || ... )
  └→ ueba.AnalyzeEvent 호출 (인라인)
       └→ 사용자 베이스라인 로드
       └→ 10개 룰 평가 (야간/주말/새 IP/대량/메신저 등)
       └→ 매칭된 룰을 anomaly_events, risk_scores에 누적
  └→ alert.Engine.Evaluate 호출 (인라인)
       └→ 룰 매칭 시 Slack 웹훅 호출
```

클립보드 에이전트도 같은 흐름. 엔드포인트는 `/api/events/clipboard`, normalize 단계만 다르다.
클립보드 변화가 없는 PC도 관리자 화면에서 살아있는지 보이도록, 에이전트는 별도로
`/api/heartbeat`를 60초마다 호출해 `endpoint_agents.last_checkin`만 갱신한다.

### 2. 관리자 페이지 조회 (사용자 타임라인)

```
브라우저 GET /audit/user/123
  ↓
chi 라우터
  ↓
JWT 미들웨어 (쿠키에서 토큰 추출, 검증, 컨텍스트 주입)
  ↓
감사 로깅 미들웨어 (status 캡처용 ResponseWriter 래핑)
  ↓
audit.UserTimelineHandler
  └→ UNION ALL: audit_logs + endpoint_events WHERE user_id=123 ORDER BY ts DESC LIMIT 100
  └→ html/template으로 audit_user.html 렌더
  ↓
응답 시점: 미들웨어가 INSERT INTO audit_logs (action='audit.view_user', target_id=123, status=200)
  ↓ DB 트리거가 hash 계산 (위와 동일)
```

### 3. 파일 업로드 (vault 사용 시)

```
브라우저 POST /api/files/upload  (multipart, 50MB .dwg 파일)
  ↓
JWT 미들웨어 + 폴더 권한 검사
  ↓
vault.UploadHandler
  └→ vault.KeyManager.GenerateFileKey()
     └→ 32바이트 랜덤 키 생성
     └→ 마스터 키로 AES-256-GCM 봉인 → ciphertext + nonce (DB 저장용)
  └→ tx 시작
       └→ INSERT INTO files (name, folder_id, encrypted_key, key_nonce, ...)
       └→ INSERT INTO file_versions (file_id, version=1, size, sha256)
       └→ vault.EncryptStream(plainKey, nonce, multipart.Reader, diskWriter)
           └→ AES-256-CTR 스트리밍, io.Copy로 64KB 청크 처리 (전체 버퍼링 없음)
           └→ /vault/{file_id}/1.enc 에 저장
  └→ tx 커밋
  ↓
감사 미들웨어가 INSERT INTO audit_logs (action='file.upload', target_id=<file_id>)
```

다운로드는 역순. `DecryptStream`이 디스크에서 스트림으로 읽으며 복호화해 HTTP 응답으로 흘려보낸다.

### 4. 백그라운드 작업

```
cron @ 매일 02:00
  └→ ueba.Analyzer.RecalculateBaselines()
       └→ 단일 SQL (LATERAL JOIN 8개):
           각 사용자에 대해 지난 30일의
           - 일평균 이벤트 수
           - 일평균 다운로드 수
           - 평일 활동 시간대 (MIN/MAX HOUR)
           - 주말 활동 여부
           - 사용한 IP 목록
           - 접속한 hostname 목록
           - 자주 사용한 파일 확장자
           계산 후 user_behavior_baselines에 UPSERT
```

알림 엔진과 UEBA 분석기는 매 이벤트마다 인라인 실행이라 별도 스케줄링 없음.

## 핵심 패턴

### 감사 미들웨어 (cross-cutting concern)

모든 인증된 HTTP 요청은 자동으로 `audit_logs`에 기록된다. 핸들러에서 별도 호출 없음.

```
internal/audit/middleware.go:Middleware()
  - statusRecorder로 ResponseWriter 래핑
  - next.ServeHTTP 호출
  - URL과 메서드로 Action enum 도출 (deriveAction)
  - chi URL 파라미터에서 target_id 추출
  - repo.Log() 호출
```

면접 포인트: "감사는 모든 엔드포인트의 공통 관심사라 핸들러에 흩어놓으면 누락 위험이 있어 미들웨어로 강제했다." 트레이드오프는 `deriveAction`이 path 매칭 기반이라 라우트 추가 시 같이 갱신해야 한다는 점.

### DB 트리거 기반 해시 체인

`audit_logs`와 `endpoint_events`는 `prev_hash`와 `row_hash` 컬럼을 갖는다. INSERT 트리거가 직전 행의 `row_hash`를 읽어 SHA256으로 체인을 만든다. UPDATE/DELETE는 트리거로 차단된다. 검증 함수가 체인을 walk해 끊긴 위치를 탐지한다.

```
migrations/008_log_integrity.up.sql:
  compute_audit_hash():
    SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1 → prev
    NEW.row_hash := SHA256(prev || NEW.user_id || NEW.action || ... )

  prevent_log_update(): RAISE EXCEPTION on UPDATE
  prevent_log_delete(): RAISE EXCEPTION on DELETE
```

면접 포인트: "어플리케이션 로직으로 강제하면 코드 우회가 가능해서 DB 레벨에서 트리거로 강제했다." 한계는 [LIMITATIONS](LIMITATIONS.md) 참고.

### Envelope encryption

파일 본체는 파일별 키로 암호화하고, 그 키는 마스터 키로 다시 암호화해 DB에 저장한다. 마스터 키 한 개만 안전하게 보관하면 된다.

```
마스터 키 (config 파일, chmod 600)
   └─ encrypts → 파일 키 A (DB의 encrypted_key 컬럼)
        └─ encrypts → 파일 A 본체 (/vault/{id}/1.enc)
```

면접 포인트: "AWS KMS 같은 KMS 패턴을 단순화한 것. 키 회전은 마스터 키 교체 후 DB의 encrypted_key 일괄 재암호화로 가능 (현재 미구현)."

### 스트리밍 I/O

50MB 이상 파일도 메모리에 전체 로드하지 않는다.

```go
// internal/vault/encryption.go
stream := cipher.NewCTR(block, nonce)
writer := &cipher.StreamWriter{S: stream, W: dst}
io.Copy(writer, src)   // 64KB 청크 단위 처리
```

면접 포인트: "`io.Reader/Writer`가 Go 표준이라 multipart 업로드 → 디스크 → 응답 전 과정이 같은 추상화로 흐른다."

### 크로스 플랫폼 에이전트

같은 `cmd/clipagent/` 코드베이스에서 Windows와 macOS 빌드. 빌드 태그로 OS별 코드를 분리한다.

```
agent.go                  공통 (enroll, send, monitor 루프)
clipboard_windows.go      //go:build windows — Win32 API
clipboard_darwin.go       //go:build darwin — pbpaste
service_windows.go        Windows SCM
service_darwin.go         launchd
```

Windows 구현은 `golang.org/x/sys/windows.NewLazySystemDLL`로 user32.dll, kernel32.dll, psapi.dll을 LazyLoad하고 `OpenClipboard`, `GetClipboardSequenceNumber`, `GetForegroundWindow`, `GetModuleBaseNameW`를 호출한다. UTF16 처리는 `windows.UTF16ToString`.

면접 포인트: "에이전트 배포가 이 선택의 핵심 동기였다. Java면 JVM, Python이면 PyInstaller가 깔려야 하지만 Go는 정적 바이너리 한 개로 끝난다."

## 기술 선택 요약

| 영역 | 선택 | 이유 |
|---|---|---|
| 언어 | Go | 크로스 플랫폼 정적 바이너리, 동시성 모델 적합. 자세한 사항: [DECISIONS](DECISIONS.md) |
| DB | PostgreSQL 단일 | 40 사용자 규모엔 Kafka/ES/Redis 불필요. tsvector로 full-text 충분 |
| 라우터 | chi | net/http 호환, 미들웨어 체인 간결 |
| DB 드라이버 | pgx | database/sql 우회로 PostgreSQL 네이티브 기능 활용 |
| UI | htmx + html/template | SPA 없이 서버 렌더 + 부분 갱신. 빌드 스텝 0 |
| 엔드포인트 | osquery 5.x | 직접 구현 안 함. 설정만 |
| 암호화 | crypto/aes (stdlib) | 외부 의존성 없음 |

## 면접 5분 설명 스크립트

> 사용자 PC에 osquery와 제가 만든 Go 클립보드 에이전트가 깔립니다. 둘 다 HTTPS로 서버에 이벤트를 POST합니다. 서버는 chi 기반 Go HTTP 서버고, 모든 요청이 JWT 인증 미들웨어와 감사 로깅 미들웨어를 거칩니다. 감사 로깅은 cross-cutting concern으로 분리해서 핸들러에서 신경 안 써도 모든 액션이 자동 기록됩니다.
>
> 데이터는 PostgreSQL에 들어갑니다. 감사 로그와 엔드포인트 이벤트 테이블엔 prev_hash와 row_hash 컬럼이 있고, INSERT 트리거가 SHA256 체인을 계산합니다. UPDATE/DELETE는 트리거로 차단해 어플리케이션이 우회할 수 없습니다. 한계는 DB 관리자 권한으론 우회 가능하다는 거고, 진짜 법적 증거 수준이 되려면 RFC 3161 같은 외부 timestamping이 필요합니다.
>
> 이상 행위 탐지는 머신러닝 없이 임계값 룰 10종으로 가중치 점수화합니다. 사용자별 베이스라인을 매일 새벽 2시에 30일치 데이터로 재계산합니다. 이건 UEBA가 아니라 rule-based anomaly scoring이라고 부르는 게 정확합니다.
>
> 파일 저장소는 envelope encryption — 파일별 키를 AES-GCM으로 마스터 키에 봉인해 DB에 저장하고, 파일 본체는 그 키로 스트리밍 암호화합니다. `io.Copy`로 청크 단위 처리해서 50MB 이상 파일도 메모리에 안 띄웁니다. 현재 본체는 CTR 모드인데 인증 태그가 없어서 무결성이 보장 안 되는 알려진 결함이 있고, 청크 GCM으로 마이그레이션 필요합니다.
>
> 프론트엔드는 htmx + Go html/template. SPA 안 만들었습니다. 빌드 스텝 없이 서버 렌더링.
