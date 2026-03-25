-- Dynamic monitoring configuration (replaces all hardcoded values)
-- All process names, extensions, paths are stored here and
-- referenced at runtime by the alert engine and osquery config generator.

-- Process groups: which processes belong to "messenger", "email", "browser", etc.
CREATE TABLE monitoring_process_groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(50) NOT NULL,       -- "messenger", "email", "browser", "screen_capture"
    process_name VARCHAR(255) NOT NULL,     -- "KakaoTalk.exe"
    display_name VARCHAR(255) NOT NULL,     -- "카카오톡"
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_name, process_name)
);

-- Monitored file extensions: which file types to track
CREATE TABLE monitoring_extensions (
    id SERIAL PRIMARY KEY,
    category VARCHAR(50) NOT NULL,         -- "document", "cad", "spreadsheet", "archive", "image"
    extension VARCHAR(20) NOT NULL,         -- ".dwg"
    display_name VARCHAR(100) NOT NULL,     -- "AutoCAD Drawing"
    is_sensitive BOOLEAN NOT NULL DEFAULT true,  -- true = triggers alerts when accessed by messenger/email
    is_active BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(extension)
);

-- Monitored paths: which directories to watch
CREATE TABLE monitoring_paths (
    id SERIAL PRIMARY KEY,
    path_type VARCHAR(50) NOT NULL,         -- "documents", "engineering", "removable", "network"
    path_pattern VARCHAR(500) NOT NULL,      -- "C:\\Users\\%\\Documents\\%%"
    description VARCHAR(255) NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Suspicious extension mappings: which "disguise" renames to detect
-- e.g., document extensions renamed to image/media extensions
CREATE TABLE monitoring_ext_disguise (
    id SERIAL PRIMARY KEY,
    from_category VARCHAR(50) NOT NULL,    -- "document", "cad"  (the real content)
    to_extension VARCHAR(20) NOT NULL,      -- ".jpg", ".mp3"    (the disguise)
    is_active BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(from_category, to_extension)
);

-- Seed default process groups
INSERT INTO monitoring_process_groups (group_name, process_name, display_name) VALUES
    -- Messengers
    ('messenger', 'KakaoTalk.exe', '카카오톡'),
    ('messenger', 'kakaotalk.exe', '카카오톡'),
    ('messenger', 'Telegram.exe', '텔레그램'),
    ('messenger', 'telegram.exe', '텔레그램'),
    ('messenger', 'Slack.exe', 'Slack'),
    ('messenger', 'slack.exe', 'Slack'),
    ('messenger', 'LINE.exe', 'LINE'),
    ('messenger', 'WeChat.exe', 'WeChat'),
    ('messenger', 'Discord.exe', 'Discord'),
    ('messenger', 'discord.exe', 'Discord'),
    ('messenger', 'Teams.exe', 'Microsoft Teams'),
    ('messenger', 'ms-teams.exe', 'Microsoft Teams'),
    -- Email clients
    ('email', 'OUTLOOK.EXE', 'Microsoft Outlook'),
    ('email', 'outlook.exe', 'Microsoft Outlook'),
    ('email', 'thunderbird.exe', 'Thunderbird'),
    ('email', 'Thunderbird.exe', 'Thunderbird'),
    ('email', 'MailMaster.exe', 'MailMaster'),
    -- Browsers
    ('browser', 'chrome.exe', 'Google Chrome'),
    ('browser', 'msedge.exe', 'Microsoft Edge'),
    ('browser', 'firefox.exe', 'Firefox'),
    ('browser', 'whale.exe', 'Naver Whale'),
    ('browser', 'brave.exe', 'Brave'),
    ('browser', 'iexplore.exe', 'Internet Explorer'),
    -- Screen capture
    ('screen_capture', 'SnippingTool.exe', '캡처 도구'),
    ('screen_capture', 'ScreenClippingHost.exe', '화면 캡처'),
    ('screen_capture', 'ShareX.exe', 'ShareX'),
    ('screen_capture', 'Lightshot.exe', 'Lightshot'),
    ('screen_capture', 'Greenshot.exe', 'Greenshot'),
    ('screen_capture', 'PicPick.exe', 'PicPick');

-- Seed monitored file extensions
INSERT INTO monitoring_extensions (category, extension, display_name, is_sensitive) VALUES
    -- CAD/Engineering (always sensitive)
    ('cad', '.dwg', 'AutoCAD Drawing', true),
    ('cad', '.dxf', 'AutoCAD Exchange', true),
    ('cad', '.stp', 'STEP 3D Model', true),
    ('cad', '.step', 'STEP 3D Model', true),
    ('cad', '.igs', 'IGES Model', true),
    ('cad', '.iges', 'IGES Model', true),
    ('cad', '.prt', 'Creo/NX Part', true),
    ('cad', '.asm', 'Creo Assembly', true),
    ('cad', '.sldprt', 'SolidWorks Part', true),
    ('cad', '.sldasm', 'SolidWorks Assembly', true),
    ('cad', '.catpart', 'CATIA Part', true),
    -- Documents
    ('document', '.pdf', 'PDF', true),
    ('document', '.doc', 'Word (Legacy)', true),
    ('document', '.docx', 'Word', true),
    ('document', '.hwp', '한글 문서', true),
    ('document', '.hwpx', '한글 문서', true),
    -- Spreadsheets
    ('spreadsheet', '.xls', 'Excel (Legacy)', true),
    ('spreadsheet', '.xlsx', 'Excel', true),
    ('spreadsheet', '.csv', 'CSV', true),
    ('spreadsheet', '.bom', 'BOM (Bill of Materials)', true),
    -- Presentations
    ('presentation', '.ppt', 'PowerPoint (Legacy)', true),
    ('presentation', '.pptx', 'PowerPoint', true),
    -- Archives (sensitive = could contain anything)
    ('archive', '.zip', 'ZIP Archive', true),
    ('archive', '.rar', 'RAR Archive', true),
    ('archive', '.7z', '7-Zip Archive', true),
    -- Text
    ('text', '.txt', 'Text File', false);

-- Seed monitored paths
INSERT INTO monitoring_paths (path_type, path_pattern, description) VALUES
    ('documents', 'C:\Users\%\Documents\%%', '사용자 문서 폴더'),
    ('documents', 'C:\Users\%\Desktop\%%', '사용자 바탕화면'),
    ('documents', 'C:\Users\%\Downloads\%%', '사용자 다운로드'),
    ('engineering', 'D:\Engineering\%%', '엔지니어링 데이터'),
    ('engineering', 'D:\CAD\%%', 'CAD 데이터'),
    ('engineering', 'E:\SharedDocs\%%', '공유 문서'),
    ('removable', 'E:\%%', '이동식 드라이브 E:'),
    ('removable', 'F:\%%', '이동식 드라이브 F:'),
    ('removable', 'G:\%%', '이동식 드라이브 G:'),
    ('removable', 'H:\%%', '이동식 드라이브 H:'),
    ('network', '\\fileserver\%%', '파일 서버'),
    ('network', '\\nas\%%', 'NAS');

-- Seed extension disguise detection rules
INSERT INTO monitoring_ext_disguise (from_category, to_extension) VALUES
    ('cad', '.jpg'), ('cad', '.jpeg'), ('cad', '.png'), ('cad', '.gif'), ('cad', '.bmp'),
    ('cad', '.mp3'), ('cad', '.mp4'), ('cad', '.avi'), ('cad', '.mkv'),
    ('cad', '.tmp'), ('cad', '.dat'), ('cad', '.log'),
    ('document', '.jpg'), ('document', '.jpeg'), ('document', '.png'), ('document', '.gif'),
    ('document', '.mp3'), ('document', '.mp4'), ('document', '.tmp'), ('document', '.dat'),
    ('spreadsheet', '.jpg'), ('spreadsheet', '.png'), ('spreadsheet', '.mp3'), ('spreadsheet', '.tmp');
