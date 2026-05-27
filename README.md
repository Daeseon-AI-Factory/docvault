# DocVault

소규모 팀(~100 엔드포인트)을 위한 자체 호스팅 내부자 위협 이벤트 수집·조회 도구.

osquery와 자체 제작 클립보드 에이전트가 사용자 PC에서 활동을 수집해 HTTPS로 서버에 보낸다. 서버는 PostgreSQL에 저장하고 웹 UI에서 조회·검색할 수 있게 한다. DB 트리거가 모든 로그에 해시 체인을 걸어 어플리케이션 레벨의 변조를 탐지한다. 임계값 룰로 야간 접근·대량 다운로드 같은 패턴을 하이라이트한다.

## 이것은

- 엔드포인트 이벤트 수집기 (파일 작업, 클립보드, USB, 메신저 접근 등)
- DB 트리거 기반 해시 체인이 적용된 감사 로그
- 임계값 룰 기반 이상 행위 점수화
- htmx 기반 조회 UI
- (옵션) AES envelope encryption 적용 파일 저장소

## 이것이 아닌

- **DRM이 아니다.** 차단하지 않고 탐지만 한다.
- **UEBA가 아니다.** 머신러닝 없이 임계값 룰 10종이다.
- **법적 증거 시스템이 아니다.** 해시 체인은 어플리케이션 레벨 변조는 막지만 DB 관리자 권한으로는 우회 가능하다.
- **프로덕션 보안 제품이 아니다.** 인증·지원·SLA 없는 개인 프로젝트다.

자세한 한계는 [docs/LIMITATIONS.md](docs/LIMITATIONS.md)를 참고.

## 빠른 실행

```bash
make build                                # bin/docvault 생성

createdb docvault
./bin/docvault migrate                    # 12개 마이그레이션 적용
./bin/docvault seed                       # admin/admin1234! 계정 생성

./bin/docvault serve                      # http://localhost:8080
```

환경 변수:
```
DOCVAULT_DB_URL=postgres://localhost/docvault
DOCVAULT_MASTER_KEY=<hex-encoded 32 bytes>
DOCVAULT_VAULT_PATH=/var/lib/docvault
DOCVAULT_JWT_SECRET=<random string>
DOCVAULT_LISTEN_ADDR=:8080
```

## 에이전트 (옵션)

```bash
# Windows 클립보드 에이전트
make clipagent-windows
docvault-clip.exe install                 # Windows 서비스 등록

# macOS 클립보드 에이전트
make clipagent-darwin

# osquery
cp deploy/osquery/* /etc/osquery/         # 또는 C:\ProgramData\osquery\
```

## 문서

| 문서 | 내용 |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | 시스템 구성, 데이터 흐름, 핵심 패턴 |
| [Decisions](docs/DECISIONS.md) | 주요 설계 결정과 트레이드오프 (ADR) |
| [Limitations](docs/LIMITATIONS.md) | 알려진 결함과 미구현 영역 |
| [Deployment](docs/DEPLOYMENT.md) | AWS EC2 배포 가이드 |
| [Spec](docs/SPEC.md) | DB 스키마·API 에러·에이전트 프로토콜 상세 |

## 기술 스택

- **Go** 1.22+ — 서버, 클립보드 에이전트
- **PostgreSQL** 16 — 이벤트·감사 로그·해시 체인 트리거
- **chi** — HTTP 라우팅
- **pgx** — PostgreSQL 드라이버
- **htmx** + Go html/template — UI
- **osquery** 5.x — 외부 엔드포인트 에이전트
- **AES-256** — envelope encryption (자세한 사항은 LIMITATIONS 참고)

## 테스트

```bash
make test-all       # 빌드 + vet + 9개 패키지 테스트
make ci             # CI 파이프라인 동일
```

## 프로젝트 구조

```
cmd/
  server/           서버 진입점 (serve, migrate, seed)
  clipagent/        Windows/macOS 클립보드 에이전트
internal/
  auth/             JWT, bcrypt, TOTP, 인증 미들웨어
  vault/            파일 암호화, 저장소, 키 관리
  audit/            감사 로깅 미들웨어, 해시 체인 검증
  endpoint/         osquery·클립보드 이벤트 수신
  alert/            룰 엔진, Slack 알림
  ueba/             임계값 기반 이상 행위 점수화
  web/              라우터, SSE, CSRF, 템플릿
  database/         연결 풀, 임베디드 마이그레이션
deploy/
  osquery/          osquery 설정
  nginx/            리버스 프록시 설정
  systemd/          Linux 서비스 유닛
  backup/           pg_dump 백업 스크립트
```

## 상태

2026년 봄 작성. 개인 포트폴리오 프로젝트. AI 어시스턴스를 사용해 빌드했으며, 핵심 모듈(해시 체인 트리거, 클립보드 에이전트, envelope encryption)은 직접 이해하고 작성했다.

## License

MIT
