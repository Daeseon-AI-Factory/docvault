# Limitations

이 문서는 DocVault의 알려진 결함, 미구현 영역, 가정의 한계를 명시한다. 면접·평가·도입 검토 시 우선적으로 봐야 할 항목.

---

## 보안 결함 (수정 필요)

### L-SEC-1 — 파일 본체에 인증되지 않은 암호화 (~~AES-CTR~~ → chunked AES-GCM, **수정됨**)

**원래 문제**: `internal/vault/encryption.go`가 파일 본체를 AES-256-CTR로 암호화하면서 MAC(인증 태그)이 없었다. 디스크의 암호화 블롭이 변조되거나 비트가 뒤집혀도 복호화가 에러 없이 성공해 사용자가 손상된 평문을 받는 결함.

**수정** (2026-05): chunked AES-256-GCM으로 교체. 64 KiB 평문 청크마다 GCM 인증 태그가 붙고, 청크별 nonce는 `file_nonce[0:8] || chunk_index (3 bytes) || final_flag (1 byte)` 로 구성된다. final_flag로 truncation 공격을 방지하고 chunk_index로 reorder 공격을 방지한다. 테스트로 검증됨:

- `TestTamperDetection`: 청크 본문 / GCM 태그 / 중간 청크 / 종료 청크 비트 플립 모두 복호화 실패
- `TestTruncationDetection`: 종료 청크 제거 시 복호화 실패
- `TestChunkReorderDetection`: 청크 순서 바꾸면 복호화 실패

**남은 트레이드오프**: GCM이 CTR보다 약간 느림(AES-NI 있으면 거의 동일). 청크당 16바이트 인증 태그 오버헤드(0.024% for 64 KiB).

### L-SEC-2 — 해시 체인의 위협 모델이 좁다

**문제**: 감사 로그 해시 체인은 어플리케이션과 외부 클라이언트의 직접 INSERT만 보호한다. PostgreSQL superuser 권한을 가진 자는:

1. `ALTER TABLE audit_logs DISABLE TRIGGER ALL`
2. 행 수정·삭제
3. 해시 재계산 후 다시 기록
4. `ENABLE TRIGGER ALL`

이 과정을 거치면 변조 흔적이 남지 않는다.

**영향**: "법적 증거(tamper-evident for legal evidence)"라고 부르기엔 약하다. 의도된 보호 대상은 *어플리케이션 버그·악의 있는 어플리케이션 사용자*에 한정된다.

**진짜 법적 증거 수준이 되려면**:
- 외부 timestamping authority (RFC 3161) 사용 — 주기적으로 체인의 head hash에 신뢰할 수 있는 timestamp 받기.
- Append-only WORM 스토리지에 같은 로그를 복제.
- DB와 별도 시스템에 row_hash 미러링.

**상태**: 인지함. README와 DECISIONS에 명시.

### L-SEC-3 — 해시 체인 동시성 race condition (**수정됨**)

**원래 문제**: `compute_audit_hash()` 트리거가 `SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1`로 직전 행을 읽는데, 직렬화 락이 없어 동시 INSERT 두 개가 같은 `prev_hash`를 읽고 체인이 분기할 수 있었다.

**수정** (2026-05): 마이그레이션 `013_audit_advisory_lock`에서 트리거 안에 `pg_advisory_xact_lock(hashtext('audit_logs_chain'))` 추가. `endpoint_events`도 동일 패턴. 락은 트랜잭션 단위라 COMMIT/ROLLBACK 시 자동 해제되고, 동일 키로 들어오는 동시 INSERT는 직렬화된다.

**남은 트레이드오프**: 해시 체인 INSERT가 테이블별로 직렬화된다. 의도된 규모(~50K 이벤트/일)에서는 무시할 수준이지만, 지속적으로 초당 10건 이상 INSERT가 발생하면 배치 처리나 다른 무결성 전략 검토 필요.

### L-SEC-4 — 에이전트 인증이 PSK 단독

**문제**: 모든 에이전트가 같은 pre-shared key (`DOCVAULT_OSQUERY_PSK`)로 인증한다. 키가 한 번 노출되면 모든 에이전트 영향. 에이전트별 개별 식별·취소가 불가능.

**해결**: 에이전트별 mTLS 인증서 발급. osquery는 mTLS 네이티브 지원. 자세한 사항은 [DECISIONS ADR-009](DECISIONS.md#adr-009--에이전트-인증에-psk-사용-개선-여지).

**상태**: 인지함. 운영 환경 배포 전 필수 개선.

### L-SEC-5 — 감사 미들웨어의 path 매칭 패턴 모호성

**문제**: `internal/audit/middleware.go:deriveAction()`이 `strings.HasSuffix(path, "/login")`처럼 suffix 매칭으로 액션을 도출한다. 다른 라우트가 추가되어 같은 suffix를 가지면 잘못된 액션으로 기록된다.

또한 89번 줄에 연산자 우선순위 문제:
```go
case method == "POST" && path == "/api/admin/users/" || method == "POST" && path == "/api/admin/users":
```
이 조건은 의도와 다르게 평가될 수 있다. 괄호 명시 필요.

**해결**: chi 라우트에 액션 메타데이터를 명시적으로 부여하거나, 라우트 등록 시점에 액션을 함께 등록.

**상태**: 인지함. 수정 미진행.

---

## 기능적 한계

### L-FUNC-1 — 차단 불가, 탐지만

osquery는 user-mode 도구다. 파일 작업이 *발생한 후* 보고할 뿐 막을 수 없다. 사용자가 USB로 기밀 파일을 복사하면 사후에 알게 된다.

**의도된 사용처**: 차단보다 사후 조사·증거 보존이 우선인 환경. 자세한 사항은 [DECISIONS ADR-003](DECISIONS.md#adr-003--차단prevention이-아니라-탐지detection).

### L-FUNC-2 — UEBA가 아니라 룰 기반 점수화

`internal/ueba/`라는 디렉토리 이름과 일부 문서의 "UEBA" 표현은 부정확하다. 실제 구현은 임계값 룰 10종 + 가중치 점수다. 머신러닝 없음.

업계에서 UEBA는 일반적으로 클러스터링·시계열 이상치 탐지·딥러닝 기반 anomaly detection을 의미한다. 이 구현은 그것과 다르다.

**정확한 이름**: rule-based anomaly scoring.

### L-FUNC-3 — 커널 레벨 가시성 없음

osquery가 user-mode라서 다음은 탐지 불가:
- 커널 모듈 적재
- 시스템 콜 후킹
- 메모리 인젝션
- 직접 디스크 I/O(파일시스템 우회)

진정한 EDR(Endpoint Detection and Response) 수준의 가시성은 커널 드라이버 또는 eBPF가 필요하다.

### L-FUNC-4 — 익스텐션 변조 탐지의 한계

`AnomalyExtDisguise`(`.dwg` → `.jpg` 같은 변조)는 SHA-256 해시 비교로 동작한다. 즉:
- 등록된 파일에 한해 탐지된다.
- 새로 만든 파일의 익스텐션 변조는 탐지 못 한다.
- 파일 내용이 1바이트라도 바뀌면 해시가 달라져 탐지 못 한다(예: 메타데이터만 수정).

진짜 익스텐션 변조 탐지는 magic byte 검사 또는 파일 시그니처 분석이 필요하다.

---

## 스케일·성능 한계

### L-SCALE-1 — 테스트 규모

검증된 규모:
- ~40 사용자
- ~50K 이벤트/일
- ~100 엔드포인트

이 이상은 **검증 안 됨**. 부하 테스트 미실시.

추정 임계점:
- 100K 이벤트/일: `endpoint_events` 인덱스 압박. 파티셔닝 필요.
- 1M 이벤트/일: PostgreSQL 단독 한계. 별도 분석 파이프라인 필요.

### L-SCALE-2 — HA 없음

단일 서버 가정. 다음은 미구현:
- 페일오버
- 멀티 인스턴스
- 로드 밸런서
- DB 복제

서버 한 대가 다운되면 서비스 전체 중단.

### L-SCALE-3 — 파일 저장소가 로컬 디스크

vault 블롭이 `DOCVAULT_VAULT_PATH`(기본 로컬 디스크)에 저장된다. S3·MinIO 같은 객체 스토리지 미지원.

디스크 단일 장애 = vault 전체 손실. `deploy/backup/backup.sh`의 rsync에 의존.

### L-SCALE-4 — 부하 테스트 미실시

`go test`는 통과한다. 그러나 실제 부하 하에서의 지표는 측정 안 했다:
- 동시 에이전트 POST 처리량
- DB 트리거 오버헤드
- 메모리 압박 시 GC 동작
- 디스크 I/O 한계

면접에서 "초당 몇 이벤트 처리 가능?" 같은 질문엔 "측정 안 했습니다"가 정직한 답.

---

## 운영 한계

### L-OPS-1 — 옵저버빌리티 없음

- 메트릭(Prometheus, OpenTelemetry) 미통합.
- 분산 트레이싱 미통합.
- 로깅은 `slog`로 stdout/stderr만.

운영 환경에선 부족하다. 추가 필요:
- `/metrics` 엔드포인트 (Prometheus 포맷)
- 헬스체크 엔드포인트(`/healthz`)는 일부 구현됨, 디테일 검증 필요.

### L-OPS-2 — 인증 없음

다음 중 어느 것도 보유하지 않음:
- KISA 인증 (한국 정보보호 인증)
- Common Criteria
- SOC 2
- ISO 27001
- FIPS 140-2 (FIPS-validated 암호 모듈 사용 안 함)

운영 환경에 도입하려면 해당 인증 비용 발생.

### L-OPS-3 — 지원 계약 없음

1인 OSS. 24/7 지원, SLA, 인시던트 대응팀 없음. 보안 패치도 best-effort.

### L-OPS-4 — 키 회전 미구현

마스터 키 교체 시 모든 `encrypted_key` 컬럼을 새 마스터 키로 재암호화하는 절차가 미구현. 수동 SQL로는 가능하지만 도구 없음.

---

## UI/UX 한계

### L-UI-1 — 모바일 미지원

`internal/web/static/style.css`는 데스크탑만 가정. 모바일 viewport 대응 안 함.

### L-UI-2 — htmx 상호작용의 round-trip

복잡한 클라이언트 상태(드래그앤드롭 트리, 실시간 필터링 등)는 매번 서버 요청. SPA 대비 응답성 떨어질 수 있음.

### L-UI-3 — i18n 없음

UI는 영어 단일 언어. 다국어 지원 미구현.

### L-UI-4 — 접근성(a11y) 검증 안 함

WCAG 준수 여부 미검증. 스크린 리더 대응 안 함.

---

## 가정의 한계 (Scope assumptions)

DocVault는 다음을 가정한다. 가정이 깨지면 의미 없음:

| 가정 | 깨지면 |
|---|---|
| 사용자 PC에 에이전트 설치 가능 | 탐지 자체가 안 됨 |
| 사용자가 admin 권한으로 OS 우회 못 함 | 에이전트 무력화 가능 |
| 회사 네트워크 안에서 동작 | 외부 침입 시 보호 약함 |
| 단일 조직 단일 테넌트 | 멀티 테넌시 미지원 |
| PostgreSQL을 신뢰함 | 해시 체인 무효 (L-SEC-2) |
| 마스터 키 보관이 안전함 | 모든 파일 키 노출 |

---

## 미구현 영역 (Roadmap, but not promised)

명시적으로 *안 만든* 것들:

- 모바일 앱 / 모바일 UI
- 멀티 테넌시
- 키 회전 도구
- 외부 IdP 통합 (SAML, OAuth)
- LDAP/AD 동기화
- 권한 위임 / 그룹 권한 (현재는 사용자 단위만)
- 파일 미리보기
- 파일 내용 기반 분류 (DLP)
- 워크플로 / 결재
- 보고서 생성 (PDF 출력)
- 알림 디지털 서명
- WORM 스토리지 통합
- 외부 timestamping (RFC 3161)
- SIEM 통합 (Splunk, ELK 전송)

이 목록은 *언젠가 하면 좋을 것*이 아니라 *현재 명시적으로 범위 밖*이다.

---

## 변경 이력

- 2026-05: 초기 작성. 알려진 결함과 미구현 영역 명시.
