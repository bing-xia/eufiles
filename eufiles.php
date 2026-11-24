<?php
/**
 * 易优PHP文件管理器 · 单文件文件管理器
 * EuPHPFileManager
 * ------------------------------------------------------------
 * 一个 PHP 文件即可运行，无需数据库；zip / tar.gz 压缩解压全部由本文件
 * 内置实现（不依赖 ZipArchive），兼容 PHP 5.2 ~ PHP 8.5（需要 zlib 扩展），
 * 可在 Windows / Linux / macOS 上运行，已针对 InfinityFree 等免费空间做受限
 * 函数兼容（无 exec / 无 disk_* 也能运行）。
 *
 * 功能：登录鉴权、多语言（简中 / 繁中 / English / 日本語 / 한국어 / Español）、普通与高级编辑器、
 *       zip 与 tar.gz 压缩解压、zip 内容在线浏览与单文件预览、
 *       全格式图片 / 音频 / 视频（含 HLS m3u8）在线预览、
 *       全选反选多选、剪切粘贴、直链分享、
 *       URL 下载、GitHub 仓库与指定版本下载、环境检测、权限与拥有者显示。
 * ------------------------------------------------------------
 * 部署：把本文件放进要管理的目录（或修改下面的 root），浏览器打开即可。
 * 首次打开会进入「首次使用引导」，按向导设置管理员账号与密码并自动登录；
 * 程序不内置任何默认密码，未完成首次设置前无法登录。
 *
 * 安全说明：账号与密码哈希、界面设置全部内嵌在本文件的数据行内，
 *           不生成也不依赖任何外置设置文件。
 *           密码统一使用 password_hash() 生成的哈希保存，本文件中不存储明文密码；
 *           低版本 PHP 由内置 polyfill 提供同等强度的 bcrypt 实现。
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
}


/* ============================================================
 * PHP 5.2+ 兼容层：以下 polyfill 仅在低版本环境中生效
 * ============================================================ */
if (!defined('PHP_VERSION_ID')) {
    $xz_seg = explode('.', PHP_VERSION);
    define('PHP_VERSION_ID', (int) $xz_seg[0] * 10000 + (int) $xz_seg[1] * 100 + (int) $xz_seg[2]);
    unset($xz_seg);
}
/* PHP 5.3 之前没有这些 JSON 常量，且 json_encode 不接受 flags 参数 */
if (!defined('JSON_HEX_TAG')) { define('JSON_HEX_TAG', 1); }
if (!defined('JSON_HEX_AMP')) { define('JSON_HEX_AMP', 2); }
if (!defined('JSON_HEX_APOS')) { define('JSON_HEX_APOS', 4); }
if (!defined('JSON_HEX_QUOT')) { define('JSON_HEX_QUOT', 8); }
if (!defined('JSON_FORCE_OBJECT')) { define('JSON_FORCE_OBJECT', 16); }
if (!defined('JSON_NUMERIC_CHECK')) { define('JSON_NUMERIC_CHECK', 32); }
if (!defined('JSON_PRETTY_PRINT')) { define('JSON_PRETTY_PRINT', 128); }
if (!defined('JSON_UNESCAPED_UNICODE')) {
    define('JSON_UNESCAPED_UNICODE', 256);
}
if (!defined('JSON_UNESCAPED_SLASHES')) {
    define('JSON_UNESCAPED_SLASHES', 64);
}
if (!defined('PASSWORD_DEFAULT')) {
    define('PASSWORD_DEFAULT', 1);
}
if (!function_exists('hash_equals')) {
    function hash_equals($known, $user)
    {
        $known = (string) $known;
        $user = (string) $user;
        if (strlen($known) !== strlen($user)) {
            return false;
        }
        $res = 0;
        for ($i = 0; $i < strlen($known); $i++) {
            $res |= ord($known[$i]) ^ ord($user[$i]);
        }
        return $res === 0;
    }
}
if (!function_exists('random_bytes')) {
    function random_bytes($length)
    {
        $length = (int) $length;
        if ($length < 1) {
            throw new Exception('random_bytes: length must be positive');
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strong = false;
            $buf = openssl_random_pseudo_bytes($length, $strong);
            if (is_string($buf) && strlen($buf) === $length) {
                return $buf;
            }
        }
        if (@is_readable('/dev/urandom')) {
            $fp = @fopen('/dev/urandom', 'rb');
            if ($fp) {
                $buf = @fread($fp, $length);
                fclose($fp);
                if (is_string($buf) && strlen($buf) === $length) {
                    return $buf;
                }
            }
        }
        $buf = '';
        while (strlen($buf) < $length) {
            $buf .= hash('sha256', uniqid((string) mt_rand(), true), true);
        }
        return substr($buf, 0, $length);
    }
}
if (!function_exists('password_hash')) {
    /* PHP 5.5 以下没有 password_hash：用 crypt 的 bcrypt 实现同等算法。
     * 加盐 16 字节，cost 10；PHP 5.3.7 之前 crypt 只认 $2a$ 前缀。 */
    function password_hash($password, $algo = 1)
    {
        if (defined('CRYPT_BLOWFISH') && CRYPT_BLOWFISH == 1) {
            $prefix = (PHP_VERSION_ID >= 50307) ? '$2y$10$' : '$2a$10$';
            $salt = substr(str_replace('+', '.', base64_encode(random_bytes(16))), 0, 22);
            $out = crypt((string) $password, $prefix . $salt);
            if (is_string($out) && strlen($out) === 60 && strpos($out, '$2') === 0) {
                return $out;
            }
        }
        // 极端环境（无 blowfish）：加盐 SHA-256 摘要，同样不保存明文
        $salt = bin2hex(random_bytes(16));
        return 'sha256:' . $salt . '$' . hash('sha256', $salt . (string) $password);
    }
}
if (!function_exists('password_verify')) {
    function password_verify($password, $hash)
    {
        $hash = (string) $hash;
        if ($hash === '') {
            return false;
        }
        if (strpos($hash, 'sha256:') === 0) {
            $body = substr($hash, 7);
            $pos = strpos($body, '$');
            if ($pos === false) {
                // 早期版本的兼容格式：sha256:<hex>
                return hash_equals($body, hash('sha256', (string) $password));
            }
            $salt = substr($body, 0, $pos);
            return hash_equals(substr($body, $pos + 1), hash('sha256', $salt . (string) $password));
        }
        if (strlen($hash) < 13) {
            return false;
        }
        // 老版本 crypt 不识别 $2y$ 前缀，改用等价的 $2a$ 校验
        $salt = $hash;
        if (PHP_VERSION_ID < 50307 && strpos($salt, '$2y$') === 0) {
            $salt = '$2a$' . substr($salt, 4);
        }
        $calc = @crypt((string) $password, $salt);
        // 与归一化后的盐串比较，兼容 $2a$ / $2y$ 两种前缀
        return is_string($calc) && $calc !== '' && hash_equals($salt, $calc);
    }
}
if (!function_exists('http_response_code')) {
    function http_response_code($code = null)
    {
        if ($code === null) {
            return 200;
        }
        $text = array(200 => 'OK', 201 => 'Created', 204 => 'No Content', 301 => 'Moved Permanently',
            302 => 'Found', 304 => 'Not Modified', 400 => 'Bad Request', 401 => 'Unauthorized',
            403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed', 409 => 'Conflict',
            410 => 'Gone', 413 => 'Payload Too Large', 415 => 'Unsupported Media Type',
            429 => 'Too Many Requests', 500 => 'Internal Server Error', 502 => 'Bad Gateway', 503 => 'Service Unavailable');
        $code = (int) $code;
        $msg = isset($text[$code]) ? $text[$code] : 'Status';
        if (!headers_sent()) {
            header('HTTP/1.1 ' . $code . ' ' . $msg, true, $code);
        }
        return $code;
    }
}
/* 兼容 PHP 7.3 之前的 setcookie 数组参数写法 */
function xz_setcookie($name, $value, $opts)
{
    if (!is_array($opts)) {
        return false;
    }
    if (PHP_VERSION_ID >= 70300) {
        return @setcookie($name, $value, $opts);
    }
    $expires = isset($opts['expires']) ? (int) $opts['expires'] : 0;
    $path = isset($opts['path']) ? (string) $opts['path'] : '';
    $domain = isset($opts['domain']) ? (string) $opts['domain'] : '';
    $secure = !empty($opts['secure']);
    $httponly = !empty($opts['httponly']);
    if (!empty($opts['samesite'])) {
        $path .= ($path === '' ? '' : '; ') . 'samesite=' . $opts['samesite'];
    }
    return @setcookie($name, $value, $expires, $path === '' ? '/' : $path, $domain, $secure, $httponly);
}

/* UTF-8 安全化：PHP 5.4 以下没有 JSON_INVALID_UTF8_SUBSTITUTE，
 * 遇到 GBK 文件名时会导致整段 JSON 编码失败，这里先转码再编码。 */
function xz_utf8($str)
{
    $str = (string) $str;
    if ($str === '' || preg_match('//u', $str)) {
        return $str;
    }
    if (function_exists('mb_convert_encoding')) {
        $out = @mb_convert_encoding($str, 'UTF-8', 'GB18030');
        if (is_string($out) && $out !== '' && preg_match('//u', $out)) {
            return $out;
        }
    }
    if (function_exists('iconv')) {
        $out = @iconv('GB18030', 'UTF-8//IGNORE', $str);
        if (is_string($out) && ($out !== '' || $str === '')) {
            return $out;
        }
    }
    return preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '?', $str);
}

function xz_json_safe($data, $depth = 0)
{
    if ($depth > 12) {
        return null;
    }
    if (is_array($data)) {
        $out = array();
        foreach ($data as $k => $v) {
            $out[is_string($k) ? xz_utf8($k) : $k] = xz_json_safe($v, $depth + 1);
        }
        return $out;
    }
    if (is_string($data)) {
        return xz_utf8($data);
    }
    if (is_bool($data) || is_int($data) || is_float($data) || $data === null) {
        return $data;
    }
    return (string) $data;
}

function xz_json_encode($data, $flags)
{
    // PHP 5.2 的 json_encode 只接受一个参数，多余参数会直接返回 null
    if (PHP_VERSION_ID < 50300) {
        $body = json_encode($data);
        if ($body === false) {
            $body = json_encode(xz_json_safe($data));
        }
        return $body;
    }
    $body = json_encode($data, $flags);
    if ($body === false && !defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $body = json_encode(xz_json_safe($data), $flags);
    }
    return $body;
}

/* 免费空间常用函数可能被 disable_functions 禁用，统一做存在性检测 */
function xz_fn_ok($name)
{
    if (!function_exists($name)) {
        return false;
    }
    $disabled = (string) ini_get('disable_functions');
    if ($disabled === '') {
        return true;
    }
    $list = array_map('trim', explode(',', strtolower($disabled)));
    return !in_array(strtolower($name), $list, true);
}

/* 大文件下载 / 解压时尽量放宽脚本超时（低版本与受限环境都安全） */
function xz_extend_time($seconds = 600)
{
    if (xz_fn_ok('set_time_limit')) {
        @set_time_limit((int) $seconds);
    }
    @ini_set('max_execution_time', (string) (int) $seconds);
}

if (session_id() === '') {
    @session_start();
}

define('XIAZZI_VERSION', 'v1.0_Eu-2026.11.23.01');
define('XIAZZI_FILE', __FILE__);
define('XIAZZI_DIR', dirname(__FILE__));

/*
 * 内嵌数据块：base64(JSON)，结构为 {v, settings:{...}, updated}
 * 全部设置保存在这一行之内，保存时程序会原子重写本文件，
 * 不生成任何外置配置文件。请勿删除或改动这一行的结构（XIAZZI_STORE）。
 */
define('XIAZZI_STORE', 'eyJ2IjozLCJzZXR0aW5ncyI6eyJsYW5nIjoiemgtQ04iLCJ0aGVtZSI6InN5c3RlbSIsInNob3dfaGlkZGVuIjp0cnVlLCJzaG93X3Blcm1zIjpmYWxzZSwiaGlkZV9zZWxmIjp0cnVlLCJlZGl0b3IiOiJub3JtYWwiLCJsYXN0X2RpciI6IiIsImdoX3Rva2VuIjoiIiwiZ2hfZXh0cmFjdCI6ZmFsc2UsImxpbmtfc3R5bGUiOiJwcmV0dHkiLCJ1c2VyIjoiYWRtaW4iLCJwYXNzX2hhc2giOiIiLCJyZW1lbWJlcl9zZWNyZXQiOiJkZDY0YzE4OWY2ZmJiM2U3YWQ3ODkyZDRjOGFjZWM3YzYzYmVlMjNhMGQ5YmYwOTAiLCJzZXR1cF9kb25lIjp0cnVlLCJzZXR1cF9hdCI6MTc5Mzc1Nzc4N30sInVwZGF0ZWQiOjE3OTM4MDM1Mzd9');

$CONFIG = array(
    // 被管理的根目录，默认是本文件所在目录
    'root'          => XIAZZI_DIR,
    // 页面标题 / 品牌名
    'title'         => '易优PHP文件管理器',
    // 是否开启登录（关闭后任何人可直接访问，请谨慎）
    'auth'          => true,
    'user'          => 'admin',
    // 不内置任何默认密码：首次访问时由「首次使用引导」设置密码，
    // 密码哈希保存在内嵌设置数据的 pass_hash 中，本文件不含明文密码。
    // 单次上传总大小上限（MB）
    'max_upload_mb' => 1024,
    // 是否显示隐藏文件
    'show_hidden'   => false,
    // 是否显示权限与拥有者
    'show_perms'    => false,
    // 是否隐藏本程序文件（设置数据内嵌其中）
    'hide_self'     => true,
    // 默认语言：zh-CN / zh-TW / en / ja / ko / es
    'lang'          => 'zh-CN',
    // 默认编辑器：normal / advanced
    'editor'        => 'normal',
    // 上传 / 新建 / URL 下载的后缀限制开关：false = 解除全部格式限制（默认）
    'restrict_ext'  => false,
    // 仅在 restrict_ext = true 时生效的禁止后缀列表
    'block_ext'     => array('php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'cgi', 'pl', 'py', 'sh', 'shtml', 'htaccess'),
    // 允许在线编辑的文本后缀
    'edit_ext'      => array('txt', 'md', 'markdown', 'json', 'js', 'mjs', 'ts', 'tsx', 'jsx', 'css', 'scss', 'less', 'html', 'htm', 'xml', 'yml', 'yaml', 'ini', 'conf', 'env', 'log', 'csv', 'sql', 'svg', 'gitignore', 'php', 'py', 'sh', 'java', 'c', 'h', 'cpp', 'go', 'rb', 'rs', 'vue', 'lock', 'toml'),
);

/* ------------------------------ 多语言 ------------------------------ */

function i18n_dict() 
{
    static $dict = null;
    if ($dict !== null) {
        return $dict;
    }
    $dict = array(
        'zh-CN' => array(
            'brand_sub' => '单文件文件管理器', 'login' => '登录', 'logout' => '退出登录',
            'user' => '用户名', 'pass' => '密码', 'pass_ph' => '请输入访问密码', 'user_ph' => '请输入用户名',
            'enter' => '进入文件管理', 'remember' => '记住这台设备', 'bad_login' => '用户名或密码不正确',
            'err_net' => '网络异常，请重试', 'loading' => '正在读取…', 'root' => '根目录',
            'files' => '文件', 'recent' => '最近', 'settings' => '设置',
            'all_files' => '全部文件', 'storage' => '存储空间', 'used' => '已用', 'free' => '可用', 'total' => '共',
            'search_ph' => '搜索当前目录及子目录', 'search' => '搜索', 'cancel' => '取消', 'ok' => '确定',
            'new_folder' => '新建文件夹', 'new_file' => '新建文件', 'upload' => '上传文件', 'upload_folder' => '上传文件夹',
            'url_dl' => 'URL 下载', 'github_dl' => 'GitHub 下载', 'name' => '名称', 'size' => '大小',
            'modified' => '修改时间', 'actions' => '操作', 'type' => '类型', 'path' => '路径', 'editable' => '可编辑', 'previewable' => '可预览', 'file_kind' => '类型', 'empty' => '这里还空着', 'empty_sub' => '点击右下角按钮上传或新建',
            'rename' => '重命名', 'copy' => '复制', 'cut' => '剪切', 'paste' => '粘贴', 'delete' => '删除',
            'more' => '更多', 'download' => '下载', 'link' => '复制直链', 'open' => '打开', 'preview' => '预览',
            'compress' => '压缩', 'extract' => '解压', 'info' => '详细信息', 'select' => '选择', 'select_all' => '全选',
            'invert' => '反选', 'none' => '全不选', 'selected' => '已选', 'items' => '项',
            'copied_tip' => '已复制到剪贴板', 'moved_tip' => '已移动', 'deleted_tip' => '已删除', 'saved_tip' => '已保存',
            'paste_here' => '粘贴到当前文件夹', 'clip_copy' => '待复制', 'clip_cut' => '待剪切', 'clear' => '清空',
            'editor' => '编辑', 'editor_normal' => '普通', 'editor_adv' => '高级', 'save' => '保存', 'unsaved' => '有未保存的修改',
            'find' => '查找', 'find_ph' => '查找内容', 'replace_ph' => '替换为', 'replace' => '替换', 'replace_all' => '全部替换',
            'ed_busy' => '正在加载文件…', 'ed_perf_big' => '大文件', 'ed_perf_huge' => '超大文件',
            'ed_perf_tip' => '性能保护：只渲染可视区域，长文件滚动与输入更流畅',
            'ed_tip_big' => '文件较大，已切换轻量渲染，编辑依然流畅',
            'ed_tip_huge' => '文件超大，已用普通模式打开并关闭语法高亮',
            'ed_hl_off' => '文件超大，高级模式已关闭语法高亮',
            'ed_paste_big' => '粘贴内容较大，可能短暂卡顿，确定继续？',
            'ed_save_big' => '文件较大，保存需要一点时间…',
            'settings_general' => '通用', 'settings_security' => '安全', 'settings_env' => '环境', 'settings_about' => '关于',
            'language' => '语言', 'theme' => '主题', 'theme_light' => '浅色', 'theme_dark' => '深色', 'theme_system' => '跟随系统',
            'create' => '新建', 'new_text' => '新建文本',
            'show_hidden' => '显示隐藏文件', 'show_perms' => '显示权限与拥有者', 'hide_self' => '隐藏程序主体文件',
            'link_style' => '直链格式', 'link_style_pretty' => '简洁路径', 'link_style_param' => '兼容参数',
            'link_sample_file' => '文件示例', 'link_sample_dir' => '文件夹示例',
            'dir_rule_hint' => '文件直链由服务器直接返回，无需额外规则；如需让 https://站点/文件夹/ 也能直接打开，在站点根目录的 .htaccess 中加入以下规则：',
            'link_style_hint' => '简洁路径：文件形如 https://站点/文件路径，文件夹形如 https://站点/文件夹/（不带 .php、不带参数）；文件夹链接需服务器把目录请求交给本程序（可用下方 RewriteRule 实现），若打开 404 请改用兼容参数',
            'gh_zip_size' => 'Zip大小',
            'default_editor' => '默认编辑器', 'change_pass' => '修改密码', 'old_pass' => '当前密码', 'new_pass' => '新密码',
            'confirm_pass' => '确认新密码', 'pass_changed' => '密码已更新', 'pass_short' => '新密码至少 6 位',
            'cred_pass_out' => '密码已更新，为保证安全已退出登录。', 'cred_user_out' => '用户名已更新，为保证安全已退出登录。', 'login_again' => '重新登录',
            'pass_mismatch' => '两次输入的密码不一致', 'sign_out' => '退出登录',
            'pass_store_hint' => '密码使用 password_hash（bcrypt）加密后保存在本文件内，不存储明文；修改密码后需重新登录。',
            'env_check' => '服务器环境检测', 'env_recheck' => '重新检测', 'check' => '检测项', 'value' => '当前值', 'state' => '状态',
            'good' => '正常', 'warn' => '注意', 'bad' => '异常', 'about_text' => '一个 PHP 单文件文件管理器，手机与桌面双端自适应。',
            'version' => '版本', 'copyright' => '版权', 'license' => '许可', 'owner' => '拥有者', 'perm' => '权限',
            'url_hint' => '粘贴文件直链，服务器会下载到当前文件夹', 'url_ph' => 'https://example.com/file.zip',
            'github_repo' => '仓库', 'github_ph' => 'owner/repo 或仓库链接', 'github_ref' => '版本 / 分支',
            'github_load' => '读取版本', 'github_pick' => '选择要下载的版本', 'github_default' => '默认分支',
            'github_token' => 'GitHub Token（可选）', 'github_token_hint' => '用于私有仓库或提高接口频率限制',
            'github_dl_btn' => '下载到当前文件夹', 'github_done' => '仓库已下载', 'token_saved' => '设置已保存',
            'gh_intro' => '功能介绍', 'gh_no_desc' => '仓库没有填写简介', 'gh_howto' => '下载说明',
            'gh_howto_1' => '选好分支或标签后，按「设置 · 通用」的下载方式保存 zip 或解压',
            'gh_mode' => '下载方式', 'gh_mode_zip' => '仅下载 zip', 'gh_mode_extract' => '解压到文件夹',
            'gh_will_zip' => '不自动解压 · 保存为 {name}', 'gh_will_extract' => '解压为文件夹 {name}',
            'gh_saved_zip' => 'zip 已保存，可在列表中解压', 'github_dl_zip_btn' => '下载 zip 到当前文件夹',
            'gh_howto_2' => '分支跟随最新提交，标签对应已发布的版本快照',
            'gh_howto_3' => '私有仓库请在「设置 · 通用」填写 GitHub Token',
            'gh_dl_mode' => 'GitHub 下载方式',
            'gh_dl_mode_hint' => '默认只保存 zip 到当前文件夹，不自动解压；选择解压会生成同名目录。',
            'gh_change_mode' => '去设置修改',
            'gh_versions' => '版本与分支', 'gh_summary' => '{b} 个分支 · {t} 个标签',
            'gh_latest' => '最新发行', 'gh_default_note' => '主开发线，通常是最新代码',
            'gh_branch_note' => '开发分支，跟随最新提交', 'gh_tag_note' => '版本快照',
            'gh_pre' => '预发行', 'gh_sel' => '已选版本', 'gh_rel_notes' => '发行说明',
            'gh_no_note' => '该版本没有发行说明，下载的是对应提交的代码快照',
            'gh_view' => '在 GitHub 查看', 'gh_updated' => '更新于', 'gh_forks' => 'Fork',
            'gh_archived' => '已归档', 'gh_branches_n' => '分支', 'gh_tags_n' => '标签',
            'rename_to' => '新名称', 'folder_name' => '文件夹名称', 'file_name' => '文件名称',
            'zip_format' => '压缩格式', 'archive_name' => '压缩包名称', 'dest_folder' => '选择目标文件夹',
            'cmp_title' => '创建压缩文件', 'cmp_create' => '创建', 'cmp_zip_level' => '压缩级别',
            'cmp_lvl_default' => '默认', 'cmp_lvl_store' => '仅存储', 'cmp_lvl_fast' => '快速', 'cmp_lvl_best' => '最小体积',
            'cmp_copy_after' => '压缩后复制直链', 'cmp_save_to' => '保存到', 'cmp_need_name' => '请输入压缩包名称',
            'yes' => '确定', 'no' => '取消', 'close' => '关闭', 'back' => '返回',
            'perm_denied' => '权限不足', 'not_found' => '文件不存在', 'copy_ok' => '复制成功',
            'recent_empty' => '还没有最近使用的文件',
            'cut_tip' => '已剪切，选择目标文件夹后粘贴', 'paste_ok' => '粘贴完成',
            'grid' => '网格', 'list' => '列表', 'sort' => '排序', 'sort_name' => '名称', 'sort_size' => '大小',
            'sort_time' => '时间', 'sort_type' => '类型', 'asc' => '升序', 'desc' => '降序', 'toggle_dir' => '切换方向',
            'uploading' => '正在上传', 'upload_done' => '上传完成', 'download_start' => '开始下载',
            'folders' => '文件夹', 'images' => '图片', 'videos' => '视频', 'audios' => '音频',
            'docs' => '文档', 'texts' => '文本', 'archives' => '压缩包',
            'no_result' => '没有找到匹配的文件', 'try_other' => '换个关键词试试',
            'delete_confirm' => '删除后不可恢复，确定继续吗？',
            'extract_to' => '解压到当前文件夹，生成目录', 'optional' => '留空则自动识别',
            'extract_title' => '解压文件', 'extract_here' => '解压到当前文件夹',
            'extract_here_hint' => '文件直接放进当前目录，重名自动改名，不覆盖原文件',
            'extract_folder' => '解压到文件夹', 'extract_folder_hint' => '新建一个文件夹收纳全部内容，可自定义名称',
            'extract_folder_name' => '文件夹名称', 'extract_go' => '开始解压',
            'undo' => '撤销', 'redo' => '重做', 'undo_done' => '已撤销', 'redo_done' => '已重做',
            'undo_empty' => '没有可撤销的操作', 'redo_empty' => '没有可重做的操作', 'hist_tip' => '编辑历史 · 最多保留 80 步',
            'no_preview' => '这种格式暂不支持在线预览', 'refresh' => '刷新',
            'pv_zoom_hint' => '双指缩放 · 双击放大', 'pv_fail_play' => '当前浏览器无法直接播放该格式',
            'pv_fail_image' => '当前浏览器无法显示该图片格式', 'pv_fail_tip' => '可下载后用本地播放器或查看器打开',
            'recent_sub' => '按修改时间排序', 'show_hidden_hint' => '显示以点开头的隐藏文件与目录',
            'show_perms_hint' => '列表与详情中显示 chmod 权限及拥有者',
            'hide_self_hint' => '在列表中隐藏本程序文件（设置已内嵌其中）', 'two_step_hint' => '修改用户名或密码后将立即退出登录',
            'session_hint' => '会话保存在服务器，退出后需重新输入密码', 'sign_out_confirm' => '确定退出登录吗？',
            'close_confirm' => '有未保存的修改，确定关闭吗？', 'copying' => '复制中',
            'change_user' => '修改用户名', 'new_user' => '新用户名', 'user_changed' => '用户名已更新',
            'backup' => '备份', 'backup_done' => '备份完成', 'backup_tip' => '在文件所在目录生成 文件名-时间戳.bak 备份',
            'goto_line' => '跳转行', 'goto_ph' => '输入行号',
            'wrap' => '自动换行', 'encoding' => '编码', 'highlight' => '语法高亮', 'line_numbers' => '行号',
            'chmod' => '修改权限', 'chmod_recursive' => '递归应用到子项', 'chmod_done' => '权限已更新',
            'move' => '移动', 'move_to' => '移动到', 'move_done' => '已移动', 'current' => '当前',
            'enc_reload' => '切换编码会重新读取文件，当前未保存的修改会丢失，继续吗？',
            'file_encoding' => '文件编码', 'enc_tab_save' => '保存编码', 'enc_tab_read' => '读取编码',
            'enc_note_save' => '保存时按此编码写出，编辑器里显示的文字不变。',
            'enc_note_read' => '按此编码重新读取文件，用于修复乱码；未保存的修改会丢失。',
            'enc_convert_save' => '转换并保存', 'enc_selected' => '保存编码已切换', 'enc_read_done' => '已按新编码重新读取',
            'enc_default' => '默认', 'enc_bom_hint' => '带 BOM',
            'advanced_only' => '该功能仅高级编辑器可用',
            'zip_preview' => '查看压缩包内容', 'zip_loading' => '正在读取压缩包…',
            'zip_files' => '个文件', 'zip_folders' => '个文件夹', 'zip_unpacked' => '解压后', 'zip_ratio' => '压缩率',
            'stat_loading' => '统计中…', 'stat_hint' => '当前文件夹（含子文件夹）的统计',
            'stat_partial' => '目录过大，统计已截断',
            'zip_search_ph' => '在压缩包内搜索', 'zip_root' => '压缩包', 'zip_empty' => '压缩包是空的',
            'zip_no_match' => '没有匹配的文件', 'zip_more' => '加载更多',
            'zip_up' => '返回上一层', 'zip_exit_search' => '退出搜索，回到当前文件夹',
            'zip_truncated' => '条目较多，仅显示前 {n} 项', 'zip_back_list' => '返回列表',
            'zip_encrypted' => '已加密', 'zip_entry_dl' => '下载此文件', 'zip_readonly' => '只读预览，不会解压到服务器',
            'zip_too_big_hint' => '文件较大，可下载后查看',
            'setup_badge' => '首次使用', 'setup_step1' => '欢迎', 'setup_step2' => '账户', 'setup_step3' => '完成',
            'setup_hello' => '先为管理后台上一把锁',
            'setup_lead' => '检测到这是第一次打开，程序尚未设置访问密码。花 30 秒创建管理员账号，之后用该账号登录。',
            'setup_p1' => '不设默认密码，首次打开即创建专属账号',
            'setup_p1_hint' => '设置完成前无法进入后台，从源头杜绝弱密码',
            'setup_p2' => '设置完成后自动登录，不用重复输入',
            'setup_p3' => '账号与密码随时可在「设置 · 安全」修改',
            'setup_start' => '开始设置',
            'setup_title' => '设置管理员账号', 'setup_sub' => '账号与密码用于以后登录，请妥善保管',
            'setup_user_label' => '管理员账号', 'setup_user_ph' => '2-32 位字母、数字或汉字',
            'setup_new_label' => '新密码', 'setup_new_ph' => '至少 8 位，含字母和数字',
            'setup_new2_label' => '确认新密码', 'setup_new2_ph' => '再次输入新密码',
            'setup_strength' => '强度', 'setup_lv1' => '弱', 'setup_lv2' => '一般', 'setup_lv3' => '良好', 'setup_lv4' => '很强',
            'setup_rule_len' => '至少 8 位', 'setup_rule_mix' => '同时包含字母与数字',
            'setup_rule_weak' => '不使用 12345678 等常见弱密码', 'setup_rule_same' => '与账号不相同',
            'setup_create' => '创建并进入', 'setup_prev' => '返回上一步', 'setup_saving' => '正在保存…',
            'setup_note' => '密码只以哈希形式保存在本文件中，不会明文存储。',
            'setup_ok' => '设置完成', 'setup_ok_sub' => '账号已创建，正在为你登录…',
            'setup_ok_user' => '管理员账号', 'setup_enter' => '进入文件管理', 'setup_retry' => '重新填写',
            'setup_ok_note' => '出于安全考虑，密码不会在这里显示，请牢记刚才设置的密码。',
            'setup_err_user' => '账号需为 2-32 位字母、数字、下划线、点、短横线或汉字',
            'setup_err_pass' => '新密码至少 8 位，且需同时包含字母和数字', 'setup_err_weak' => '这个密码太常见，请换一个',
            'setup_err_pass2' => '两次输入的密码不一致', 'setup_err_same' => '新密码不能与账号相同',
            'setup_err_save' => '保存失败，请检查本文件是否可写（建议权限 644 或 755）',
            'setup_done_already' => '初始化已完成，请直接登录', 'setup_net' => '网络异常，请重试',
            'setup_app_title' => '完成安全设置', 'setup_app_sub' => '首次使用需设置专属账号密码',
            'setup_exit' => '退出登录', 'setup_show_pass' => '显示密码', 'setup_hide_pass' => '隐藏密码',

        ),
        'zh-TW' => array(
            'brand_sub' => '單檔檔案管理器', 'login' => '登入', 'logout' => '登出',
            'user' => '使用者名稱', 'pass' => '密碼', 'pass_ph' => '請輸入存取密碼', 'user_ph' => '請輸入使用者名稱',
            'enter' => '進入檔案管理', 'remember' => '記住這台裝置', 'bad_login' => '使用者名稱或密碼不正確',
            'err_net' => '網路異常，請重試', 'loading' => '正在讀取…', 'root' => '根目錄',
            'files' => '檔案', 'recent' => '最近', 'settings' => '設定',
            'all_files' => '全部檔案', 'storage' => '儲存空間', 'used' => '已用', 'free' => '可用', 'total' => '共',
            'search_ph' => '搜尋目前目錄及子目錄', 'search' => '搜尋', 'cancel' => '取消', 'ok' => '確定',
            'new_folder' => '新增資料夾', 'new_file' => '新增檔案', 'upload' => '上傳檔案', 'upload_folder' => '上傳資料夾',
            'url_dl' => 'URL 下載', 'github_dl' => 'GitHub 下載', 'name' => '名稱', 'size' => '大小',
            'modified' => '修改時間', 'actions' => '操作', 'type' => '類型', 'path' => '路徑', 'editable' => '可編輯', 'previewable' => '可預覽', 'file_kind' => '類型', 'empty' => '這裡還空著', 'empty_sub' => '點擊右下角按鈕上傳或新增',
            'rename' => '重新命名', 'copy' => '複製', 'cut' => '剪下', 'paste' => '貼上', 'delete' => '刪除',
            'more' => '更多', 'download' => '下載', 'link' => '複製直連', 'open' => '開啟', 'preview' => '預覽',
            'compress' => '壓縮', 'extract' => '解壓縮', 'info' => '詳細資訊', 'select' => '選取', 'select_all' => '全選',
            'invert' => '反選', 'none' => '全不選', 'selected' => '已選', 'items' => '項',
            'copied_tip' => '已複製到剪貼簿', 'moved_tip' => '已移動', 'deleted_tip' => '已刪除', 'saved_tip' => '已儲存',
            'paste_here' => '貼上到目前資料夾', 'clip_copy' => '待複製', 'clip_cut' => '待剪下', 'clear' => '清空',
            'editor' => '編輯', 'editor_normal' => '一般', 'editor_adv' => '進階', 'save' => '儲存', 'unsaved' => '有未儲存的修改',
            'find' => '尋找', 'find_ph' => '尋找內容', 'replace_ph' => '取代為', 'replace' => '取代', 'replace_all' => '全部取代',
            'ed_busy' => '正在載入檔案…', 'ed_perf_big' => '大檔案', 'ed_perf_huge' => '超大檔案',
            'ed_perf_tip' => '效能保護：只渲染可視區域，長檔案捲動與輸入更順暢',
            'ed_tip_big' => '檔案較大，已切換為輕量渲染，編輯依然順暢',
            'ed_tip_huge' => '檔案超大，已用一般模式開啟並關閉語法高亮',
            'ed_hl_off' => '檔案超大，進階模式已關閉語法高亮',
            'ed_paste_big' => '貼上內容較大，可能短暫卡頓，確定繼續？',
            'ed_save_big' => '檔案較大，儲存需要一點時間…',
            'settings_general' => '一般', 'settings_security' => '安全', 'settings_env' => '環境', 'settings_about' => '關於',
            'language' => '語言', 'theme' => '主題', 'theme_light' => '淺色', 'theme_dark' => '深色', 'theme_system' => '跟隨系統',
            'create' => '新增', 'new_text' => '新增文字檔',
            'show_hidden' => '顯示隱藏檔案', 'show_perms' => '顯示權限與擁有者', 'hide_self' => '隱藏程式主體檔案',
            'link_style' => '直連格式', 'link_style_pretty' => '簡潔路徑', 'link_style_param' => '相容參數',
            'link_sample_file' => '檔案示例', 'link_sample_dir' => '資料夾示例',
            'dir_rule_hint' => '檔案直連由伺服器直接回傳，無需額外規則；如需讓 https://站點/資料夾/ 也能直接開啟，在站點根目錄的 .htaccess 中加入以下規則：',
            'link_style_hint' => '簡潔路徑：檔案形如 https://站點/檔案路徑，資料夾形如 https://站點/資料夾/（不帶 .php、不帶參數）；資料夾連結需伺服器把目錄請求交給本程式（可用下方 RewriteRule 實現），若開啟 404 請改用相容參數',
            'gh_zip_size' => 'Zip大小',
            'default_editor' => '預設編輯器', 'change_pass' => '修改密碼', 'old_pass' => '目前密碼', 'new_pass' => '新密碼',
            'confirm_pass' => '確認新密碼', 'pass_changed' => '密碼已更新', 'pass_short' => '新密碼至少 6 位',
            'cred_pass_out' => '密碼已更新，為確保安全已登出。', 'cred_user_out' => '使用者名稱已更新，為確保安全已登出。', 'login_again' => '重新登入',
            'pass_mismatch' => '兩次輸入的密碼不一致', 'sign_out' => '登出',
            'pass_store_hint' => '密碼使用 password_hash（bcrypt）加密後儲存在本檔案內，不儲存明文；修改密碼後需重新登入。',
            'env_check' => '伺服器環境檢測', 'env_recheck' => '重新檢測', 'check' => '檢測項', 'value' => '目前值', 'state' => '狀態',
            'good' => '正常', 'warn' => '注意', 'bad' => '異常', 'about_text' => '一個 PHP 單檔檔案管理器，手機與桌面雙端自適應。',
            'version' => '版本', 'copyright' => '版權', 'license' => '授權', 'owner' => '擁有者', 'perm' => '權限',
            'url_hint' => '貼上檔案直連，伺服器會下載到目前資料夾', 'url_ph' => 'https://example.com/file.zip',
            'github_repo' => '儲存庫', 'github_ph' => 'owner/repo 或儲存庫連結', 'github_ref' => '版本 / 分支',
            'github_load' => '讀取版本', 'github_pick' => '選擇要下載的版本', 'github_default' => '預設分支',
            'github_token' => 'GitHub Token（選填）', 'github_token_hint' => '用於私有儲存庫或提高 API 頻率限制',
            'github_dl_btn' => '下載到目前資料夾', 'github_done' => '儲存庫已下載', 'token_saved' => '設定已儲存',
            'gh_intro' => '功能介紹', 'gh_no_desc' => '儲存庫沒有填寫簡介', 'gh_howto' => '下載說明',
            'gh_howto_1' => '選好分支或標籤後，依「設定 · 一般」的下載方式儲存 zip 或解壓縮',
            'gh_mode' => '下載方式', 'gh_mode_zip' => '僅下載 zip', 'gh_mode_extract' => '解壓縮到資料夾',
            'gh_will_zip' => '不自動解壓縮 · 儲存為 {name}', 'gh_will_extract' => '解壓縮為資料夾 {name}',
            'gh_saved_zip' => 'zip 已儲存，可在清單中解壓縮', 'github_dl_zip_btn' => '下載 zip 到目前資料夾',
            'gh_howto_2' => '分支跟隨最新提交，標籤對應已發佈的版本快照',
            'gh_howto_3' => '私有儲存庫請在「設定 · 一般」填寫 GitHub Token',
            'gh_dl_mode' => 'GitHub 下載方式',
            'gh_dl_mode_hint' => '預設只儲存 zip 到目前資料夾，不自動解壓縮；選擇解壓縮會產生同名目錄。',
            'gh_change_mode' => '去設定修改',
            'gh_versions' => '版本與分支', 'gh_summary' => '{b} 個分支 · {t} 個標籤',
            'gh_latest' => '最新發行', 'gh_default_note' => '主開發線，通常是最新程式碼',
            'gh_branch_note' => '開發分支，跟隨最新提交', 'gh_tag_note' => '版本快照',
            'gh_pre' => '預發行', 'gh_sel' => '已選版本', 'gh_rel_notes' => '發行說明',
            'gh_no_note' => '該版本沒有發行說明，下載的是對應提交的程式碼快照',
            'gh_view' => '在 GitHub 查看', 'gh_updated' => '更新於', 'gh_forks' => 'Fork',
            'gh_archived' => '已封存', 'gh_branches_n' => '分支', 'gh_tags_n' => '標籤',
            'rename_to' => '新名稱', 'folder_name' => '資料夾名稱', 'file_name' => '檔案名稱',
            'zip_format' => '壓縮格式', 'archive_name' => '壓縮檔名稱', 'dest_folder' => '選擇目標資料夾',
            'cmp_title' => '建立壓縮檔', 'cmp_create' => '建立', 'cmp_zip_level' => '壓縮等級',
            'cmp_lvl_default' => '預設', 'cmp_lvl_store' => '僅儲存', 'cmp_lvl_fast' => '快速', 'cmp_lvl_best' => '最小體積',
            'cmp_copy_after' => '壓縮後複製直連', 'cmp_save_to' => '儲存到', 'cmp_need_name' => '請輸入壓縮檔名稱',
            'yes' => '確定', 'no' => '取消', 'close' => '關閉', 'back' => '返回',
            'perm_denied' => '權限不足', 'not_found' => '檔案不存在', 'copy_ok' => '複製成功',
            'recent_empty' => '還沒有最近使用的檔案',
            'cut_tip' => '已剪下，選擇目標資料夾後貼上', 'paste_ok' => '貼上完成',
            'grid' => '格狀', 'list' => '列表', 'sort' => '排序', 'sort_name' => '名稱', 'sort_size' => '大小',
            'sort_time' => '時間', 'sort_type' => '類型', 'asc' => '遞增', 'desc' => '遞減', 'toggle_dir' => '切換方向',
            'uploading' => '正在上傳', 'upload_done' => '上傳完成', 'download_start' => '開始下載',
            'folders' => '資料夾', 'images' => '圖片', 'videos' => '影片', 'audios' => '音訊',
            'docs' => '文件', 'texts' => '文字', 'archives' => '壓縮檔',
            'no_result' => '找不到符合的檔案', 'try_other' => '換個關鍵字試試',
            'delete_confirm' => '刪除後無法復原，確定繼續嗎？',
            'extract_to' => '解壓縮到目前資料夾，產生目錄', 'optional' => '留空則自動辨識',
            'extract_title' => '解壓縮檔案', 'extract_here' => '解壓縮到目前資料夾',
            'extract_here_hint' => '檔案直接放進目前目錄，重名自動改名，不覆蓋原檔',
            'extract_folder' => '解壓縮到資料夾', 'extract_folder_hint' => '建立資料夾收納全部內容，可自訂名稱',
            'extract_folder_name' => '資料夾名稱', 'extract_go' => '開始解壓縮',
            'undo' => '復原', 'redo' => '重做', 'undo_done' => '已復原', 'redo_done' => '已重做',
            'undo_empty' => '沒有可復原的操作', 'redo_empty' => '沒有可重做的操作', 'hist_tip' => '編輯歷史 · 最多保留 80 步',
            'no_preview' => '這種格式暫不支援線上預覽', 'refresh' => '重新整理',
            'pv_zoom_hint' => '雙指縮放 · 雙擊放大', 'pv_fail_play' => '目前瀏覽器無法直接播放此格式',
            'pv_fail_image' => '目前瀏覽器無法顯示此圖片格式', 'pv_fail_tip' => '可下載後用本機播放器或檢視器開啟',
            'recent_sub' => '依修改時間排序', 'show_hidden_hint' => '顯示以點開頭的隱藏檔案與目錄',
            'show_perms_hint' => '列表與詳細資訊中顯示 chmod 權限及擁有者',
            'hide_self_hint' => '在列表中隱藏本程式檔（設定已內嵌其中）', 'two_step_hint' => '修改使用者名稱或密碼後將立即登出',
            'session_hint' => '工作階段保存在伺服器，登出後需重新輸入密碼', 'sign_out_confirm' => '確定登出嗎？',
            'close_confirm' => '有未儲存的修改，確定關閉嗎？', 'copying' => '複製中',
            'zip_preview' => '檢視壓縮檔內容', 'zip_loading' => '正在讀取壓縮檔…',
            'zip_files' => '個檔案', 'zip_folders' => '個資料夾', 'zip_unpacked' => '解壓後', 'zip_ratio' => '壓縮率',
            'stat_loading' => '統計中…', 'stat_hint' => '目前資料夾（含子資料夾）的統計',
            'stat_partial' => '目錄過大，統計已截斷',
            'zip_search_ph' => '在壓縮檔內搜尋', 'zip_root' => '壓縮檔', 'zip_empty' => '壓縮檔是空的',
            'zip_no_match' => '沒有符合的檔案', 'zip_more' => '載入更多',
            'zip_up' => '返回上一層', 'zip_exit_search' => '退出搜尋，回到目前資料夾',
            'zip_truncated' => '項目較多，僅顯示前 {n} 項', 'zip_back_list' => '返回列表',
            'zip_encrypted' => '已加密', 'zip_entry_dl' => '下載此檔案', 'zip_readonly' => '唯讀預覽，不會解壓縮到伺服器',
            'zip_too_big_hint' => '檔案較大，可下載後檢視',
            'setup_badge' => '首次使用', 'setup_step1' => '歡迎', 'setup_step2' => '帳戶', 'setup_step3' => '完成',
            'setup_hello' => '先為管理後台上把鎖',
            'setup_lead' => '偵測到這是第一次開啟，程式尚未設定存取密碼。花 30 秒建立管理員帳號，之後用該帳號登入。',
            'setup_p1' => '不設預設密碼，首次開啟即建立專屬帳號',
            'setup_p1_hint' => '設定完成前無法進入後台，從源頭杜絕弱密碼',
            'setup_p2' => '設定完成後自動登入，不用重複輸入',
            'setup_p3' => '帳號與密碼隨時可在「設定 · 安全」修改',
            'setup_start' => '開始設定',
            'setup_title' => '設定管理員帳號', 'setup_sub' => '帳號與密碼用於之後登入，請妥善保管',
            'setup_user_label' => '管理員帳號', 'setup_user_ph' => '2-32 位字母、數字或漢字',
            'setup_new_label' => '新密碼', 'setup_new_ph' => '至少 8 位，含字母和數字',
            'setup_new2_label' => '確認新密碼', 'setup_new2_ph' => '再次輸入新密碼',
            'setup_strength' => '強度', 'setup_lv1' => '弱', 'setup_lv2' => '一般', 'setup_lv3' => '良好', 'setup_lv4' => '很強',
            'setup_rule_len' => '至少 8 位', 'setup_rule_mix' => '同時包含字母與數字',
            'setup_rule_weak' => '不使用 12345678 等常見弱密碼', 'setup_rule_same' => '與帳號不相同',
            'setup_create' => '建立並進入', 'setup_prev' => '返回上一步', 'setup_saving' => '正在儲存…',
            'setup_note' => '密碼只以雜湊形式保存在本檔案中，不會明文儲存。',
            'setup_ok' => '設定完成', 'setup_ok_sub' => '帳號已建立，正在為你登入…',
            'setup_ok_user' => '管理員帳號', 'setup_enter' => '進入檔案管理', 'setup_retry' => '重新填寫',
            'setup_ok_note' => '出於安全考量，密碼不會在這裡顯示，請牢記剛才設定的密碼。',
            'setup_err_user' => '帳號需為 2-32 位字母、數字、底線、點、短橫線或漢字',
            'setup_err_pass' => '新密碼至少 8 位，且需同時包含字母和數字', 'setup_err_weak' => '這個密碼太常見，請換一個',
            'setup_err_pass2' => '兩次輸入的密碼不一致', 'setup_err_same' => '新密碼不能與帳號相同',
            'setup_err_save' => '儲存失敗，請檢查本檔案是否可寫（建議權限 644 或 755）',
            'setup_done_already' => '初始化已完成，請直接登入', 'setup_net' => '網路異常，請重試',
            'setup_app_title' => '完成安全設定', 'setup_app_sub' => '首次使用需設定專屬帳號密碼',
            'setup_exit' => '登出', 'setup_show_pass' => '顯示密碼', 'setup_hide_pass' => '隱藏密碼',

        ),
        'en' => array(
            'brand_sub' => 'Single-file file manager', 'login' => 'Sign in', 'logout' => 'Sign out',
            'user' => 'Username', 'pass' => 'Password', 'pass_ph' => 'Enter password', 'user_ph' => 'Enter username',
            'enter' => 'Open file manager', 'remember' => 'Remember this device', 'bad_login' => 'Incorrect username or password',
            'err_net' => 'Network error, please retry', 'loading' => 'Loading…', 'root' => 'Root',
            'files' => 'Files', 'recent' => 'Recent', 'settings' => 'Settings',
            'all_files' => 'All files', 'storage' => 'Storage', 'used' => 'Used', 'free' => 'Free', 'total' => 'Total',
            'search_ph' => 'Search this folder and below', 'search' => 'Search', 'cancel' => 'Cancel', 'ok' => 'OK',
            'new_folder' => 'New folder', 'new_file' => 'New file', 'upload' => 'Upload files', 'upload_folder' => 'Upload folder',
            'url_dl' => 'Download from URL', 'github_dl' => 'Download from GitHub', 'name' => 'Name', 'size' => 'Size',
            'modified' => 'Modified', 'actions' => 'Actions', 'type' => 'Type', 'path' => 'Path', 'editable' => 'Editable', 'previewable' => 'Preview', 'file_kind' => 'Type', 'empty' => 'Nothing here yet', 'empty_sub' => 'Tap the button at bottom right to upload',
            'rename' => 'Rename', 'copy' => 'Copy', 'cut' => 'Cut', 'paste' => 'Paste', 'delete' => 'Delete',
            'more' => 'More', 'download' => 'Download', 'link' => 'Copy direct link', 'open' => 'Open', 'preview' => 'Preview',
            'compress' => 'Compress', 'extract' => 'Extract', 'info' => 'Details', 'select' => 'Select', 'select_all' => 'Select all',
            'invert' => 'Invert', 'none' => 'Select none', 'selected' => 'Selected', 'items' => '',
            'copied_tip' => 'Copied to clipboard', 'moved_tip' => 'Moved', 'deleted_tip' => 'Deleted', 'saved_tip' => 'Saved',
            'paste_here' => 'Paste into this folder', 'clip_copy' => 'to copy', 'clip_cut' => 'to move', 'clear' => 'Clear',
            'editor' => 'Edit', 'editor_normal' => 'Basic', 'editor_adv' => 'Advanced', 'save' => 'Save', 'unsaved' => 'Unsaved changes',
            'find' => 'Find', 'find_ph' => 'Find', 'replace_ph' => 'Replace with', 'replace' => 'Replace', 'replace_all' => 'Replace all',
            'ed_busy' => 'Loading file…', 'ed_perf_big' => 'Large file', 'ed_perf_huge' => 'Huge file',
            'ed_perf_tip' => 'Performance guard: only the visible area is rendered',
            'ed_tip_big' => 'Large file: switched to lightweight rendering',
            'ed_tip_huge' => 'Huge file: opened in basic mode, highlighting off',
            'ed_hl_off' => 'Huge file: syntax highlighting is off',
            'ed_paste_big' => 'Pasted text is large and may lag briefly. Continue?',
            'ed_save_big' => 'Large file: saving may take a moment…',
            'settings_general' => 'General', 'settings_security' => 'Security', 'settings_env' => 'Environment', 'settings_about' => 'About',
            'language' => 'Language', 'theme' => 'Theme', 'theme_light' => 'Light', 'theme_dark' => 'Dark', 'theme_system' => 'System',
            'create' => 'New', 'new_text' => 'New text file',
            'show_hidden' => 'Show hidden files', 'show_perms' => 'Show permissions & owner', 'hide_self' => 'Hide program file',
            'link_style' => 'Direct link format', 'link_style_pretty' => 'Clean path', 'link_style_param' => 'Compat params',
            'link_sample_file' => 'File sample', 'link_sample_dir' => 'Folder sample',
            'dir_rule_hint' => 'File links are served directly by the web server and need no extra rules; to make https://site/folder/ open directly, add these rules to .htaccess in the site root:',
            'link_style_hint' => 'Clean path: files look like https://site/path/to/file, folders look like https://site/folder/ (no .php, no params). Folder links need the server to route directory requests to this script (a .htaccess RewriteRule works); switch to Compat params if you get a 404',
            'gh_zip_size' => 'Zip size',
            'default_editor' => 'Default editor', 'change_pass' => 'Change password', 'old_pass' => 'Current password', 'new_pass' => 'New password',
            'confirm_pass' => 'Confirm password', 'pass_changed' => 'Password updated', 'pass_short' => 'At least 6 characters',
            'cred_pass_out' => 'Password updated. You have been signed out for security.', 'cred_user_out' => 'Username updated. You have been signed out for security.', 'login_again' => 'Sign in again',
            'pass_mismatch' => 'Passwords do not match', 'sign_out' => 'Sign out',
            'pass_store_hint' => 'Passwords are stored as password_hash (bcrypt) hashes inside this file, never in plain text. You will be signed out after changing the password.',
            'env_check' => 'Server environment', 'env_recheck' => 'Re-check', 'check' => 'Check', 'value' => 'Value', 'state' => 'State',
            'good' => 'OK', 'warn' => 'Warning', 'bad' => 'Error', 'about_text' => 'A single-file PHP file manager, responsive on mobile and desktop.',
            'version' => 'Version', 'copyright' => 'Copyright', 'license' => 'License', 'owner' => 'Owner', 'perm' => 'Permissions',
            'url_hint' => 'Paste a direct file URL, the server saves it into this folder', 'url_ph' => 'https://example.com/file.zip',
            'github_repo' => 'Repository', 'github_ph' => 'owner/repo or repository URL', 'github_ref' => 'Version / branch',
            'github_load' => 'Load versions', 'github_pick' => 'Pick a version', 'github_default' => 'Default branch',
            'github_token' => 'GitHub token (optional)', 'github_token_hint' => 'For private repositories or higher rate limits',
            'github_dl_btn' => 'Download into this folder', 'github_done' => 'Repository downloaded', 'token_saved' => 'Settings saved',
            'gh_intro' => 'About this project', 'gh_no_desc' => 'No description provided', 'gh_howto' => 'How it works',
            'gh_howto_1' => 'Pick a branch or tag; the zip is saved or unpacked as set in Settings · General',
            'gh_mode' => 'Delivery', 'gh_mode_zip' => 'Zip only', 'gh_mode_extract' => 'Unpack here',
            'gh_will_zip' => 'Keep as zip · {name}', 'gh_will_extract' => 'Unpack into {name}',
            'gh_saved_zip' => 'Zip saved, unpack it from the list', 'github_dl_zip_btn' => 'Download zip here',
            'gh_howto_2' => 'Branches follow the latest commit, tags are released snapshots',
            'gh_howto_3' => 'For private repositories add a GitHub token in Settings · General',
            'gh_dl_mode' => 'GitHub download mode',
            'gh_dl_mode_hint' => 'By default the zip is saved as-is without unpacking. Choose unpack to create a folder with the same name.',
            'gh_change_mode' => 'Change in settings',
            'gh_versions' => 'Versions & branches', 'gh_summary' => '{b} branches · {t} tags',
            'gh_latest' => 'Latest release', 'gh_default_note' => 'Main line of development',
            'gh_branch_note' => 'Development branch, follows latest commits', 'gh_tag_note' => 'Release snapshot',
            'gh_pre' => 'Pre-release', 'gh_sel' => 'Selected', 'gh_rel_notes' => 'Release notes',
            'gh_no_note' => 'No release notes for this version; the commit snapshot is downloaded',
            'gh_view' => 'View on GitHub', 'gh_updated' => 'Updated', 'gh_forks' => 'Forks',
            'gh_archived' => 'Archived', 'gh_branches_n' => 'branches', 'gh_tags_n' => 'tags',
            'rename_to' => 'New name', 'folder_name' => 'Folder name', 'file_name' => 'File name',
            'zip_format' => 'Format', 'archive_name' => 'Archive name', 'dest_folder' => 'Destination folder',
            'cmp_title' => 'Create archive', 'cmp_create' => 'Create', 'cmp_zip_level' => 'Compression',
            'cmp_lvl_default' => 'Default', 'cmp_lvl_store' => 'Store only', 'cmp_lvl_fast' => 'Fast', 'cmp_lvl_best' => 'Smallest',
            'cmp_copy_after' => 'Copy link after', 'cmp_save_to' => 'Save to', 'cmp_need_name' => 'Enter an archive name',
            'file_encoding' => 'File encoding', 'enc_tab_save' => 'Save as', 'enc_tab_read' => 'Reopen as',
            'enc_note_save' => 'The file is written in this encoding; the text on screen stays the same.',
            'enc_note_read' => 'Re-read the file with this encoding to fix garbled text. Unsaved edits are lost.',
            'enc_convert_save' => 'Convert & save', 'enc_selected' => 'Save encoding changed', 'enc_read_done' => 'Reopened',
            'enc_default' => 'Default', 'enc_bom_hint' => 'BOM',
            'yes' => 'OK', 'no' => 'Cancel', 'close' => 'Close', 'back' => 'Back',
            'perm_denied' => 'Permission denied', 'not_found' => 'Path not found', 'copy_ok' => 'Copied',
            'recent_empty' => 'No recent files yet',
            'cut_tip' => 'Cut. Open the target folder and paste', 'paste_ok' => 'Pasted',
            'grid' => 'Grid', 'list' => 'List', 'sort' => 'Sort', 'sort_name' => 'Name', 'sort_size' => 'Size',
            'sort_time' => 'Time', 'sort_type' => 'Type', 'asc' => 'Ascending', 'desc' => 'Descending', 'toggle_dir' => 'Reverse',
            'uploading' => 'Uploading', 'upload_done' => 'Upload complete', 'download_start' => 'Download started',
            'folders' => 'Folder', 'images' => 'Images', 'videos' => 'Videos', 'audios' => 'Audio',
            'docs' => 'Documents', 'texts' => 'Text', 'archives' => 'Archives',
            'no_result' => 'No matching files', 'try_other' => 'Try another keyword',
            'delete_confirm' => 'This cannot be undone. Continue?',
            'extract_to' => 'Extracts into a new folder here', 'optional' => 'Leave empty to auto-detect',
            'extract_title' => 'Extract archive', 'extract_here' => 'Extract to current folder',
            'extract_here_hint' => 'Files land right here; duplicates are renamed, nothing is overwritten',
            'extract_folder' => 'Extract into a folder', 'extract_folder_hint' => 'Create one folder for everything; name is editable',
            'extract_folder_name' => 'Folder name', 'extract_go' => 'Extract',
            'undo' => 'Undo', 'redo' => 'Redo', 'undo_done' => 'Undone', 'redo_done' => 'Redone',
            'undo_empty' => 'Nothing to undo', 'redo_empty' => 'Nothing to redo', 'hist_tip' => 'Edit history · up to 80 steps',
            'no_preview' => 'Preview is not available for this format', 'refresh' => 'Refresh',
            'pv_zoom_hint' => 'Pinch to zoom · double-tap to enlarge', 'pv_fail_play' => 'This browser cannot play this format inline',
            'pv_fail_image' => 'This browser cannot display this image format', 'pv_fail_tip' => 'Download it and open it with a local player or viewer',
            'recent_sub' => 'Sorted by modified time', 'show_hidden_hint' => 'Show dotfiles and hidden folders',
            'show_perms_hint' => 'Show chmod permissions and owner in list and details',
            'hide_self_hint' => 'Hide this program file (settings are embedded in it)', 'two_step_hint' => 'Changing username or password signs you out at once',
            'session_hint' => 'The session lives on the server', 'sign_out_confirm' => 'Sign out now?',
            'close_confirm' => 'You have unsaved changes. Close anyway?', 'copying' => 'Copying',
            'zip_preview' => 'Browse archive', 'zip_loading' => 'Reading archive…',
            'zip_files' => 'files', 'zip_folders' => 'folders', 'zip_unpacked' => 'Unpacked', 'zip_ratio' => 'Compression',
            'stat_loading' => 'Counting…', 'stat_hint' => 'Totals for this folder and its subfolders',
            'stat_partial' => 'Folder too large; counts truncated',
            'zip_search_ph' => 'Search inside archive', 'zip_root' => 'Archive', 'zip_empty' => 'This archive is empty',
            'zip_no_match' => 'No matching files', 'zip_more' => 'Load more',
            'zip_up' => 'Back to parent folder', 'zip_exit_search' => 'Exit search and return to this folder',
            'zip_truncated' => 'Too many entries; showing the first {n}', 'zip_back_list' => 'Back to list',
            'zip_encrypted' => 'Encrypted', 'zip_entry_dl' => 'Download this file', 'zip_readonly' => 'Read-only preview; nothing is extracted to the server',
            'zip_too_big_hint' => 'File is large; download it to view',
            'setup_badge' => 'First run', 'setup_step1' => 'Welcome', 'setup_step2' => 'Account', 'setup_step3' => 'Done',
            'setup_hello' => 'Put a lock on your file manager',
            'setup_lead' => 'This is a first run and no password has been set yet. Take 30 seconds to create your admin account, then sign in with it.',
            'setup_p1' => 'No default password; you create your own account on first run',
            'setup_p1_hint' => 'Nobody can get in until setup is complete',
            'setup_p2' => 'You will be signed in automatically after setup',
            'setup_p3' => 'You can change both later in Settings · Security',
            'setup_start' => 'Get started',
            'setup_title' => 'Create your admin account', 'setup_sub' => 'These credentials will be used to sign in from now on',
            'setup_user_label' => 'Admin username', 'setup_user_ph' => '2-32 letters, digits or CJK characters',
            'setup_new_label' => 'New password', 'setup_new_ph' => 'At least 8 characters with letters and digits',
            'setup_new2_label' => 'Confirm password', 'setup_new2_ph' => 'Repeat the new password',
            'setup_strength' => 'Strength', 'setup_lv1' => 'Weak', 'setup_lv2' => 'Fair', 'setup_lv3' => 'Good', 'setup_lv4' => 'Strong',
            'setup_rule_len' => 'At least 8 characters', 'setup_rule_mix' => 'Contains letters and digits',
            'setup_rule_weak' => 'Not a common password such as 12345678', 'setup_rule_same' => 'Different from the username',
            'setup_create' => 'Create and continue', 'setup_prev' => 'Back', 'setup_saving' => 'Saving…',
            'setup_note' => 'The password is stored as a hash inside this file; never in plain text.',
            'setup_ok' => 'All set', 'setup_ok_sub' => 'Your account is ready. Signing you in…',
            'setup_ok_user' => 'Admin username', 'setup_enter' => 'Open file manager', 'setup_retry' => 'Edit again',
            'setup_ok_note' => 'For security the password is never shown here; please keep it safe.',
            'setup_err_user' => 'Use 2-32 letters, digits, underscore, dot, hyphen or CJK characters',
            'setup_err_pass' => 'Use at least 8 characters including letters and digits', 'setup_err_weak' => 'That password is too common; pick another',
            'setup_err_pass2' => 'The two passwords do not match', 'setup_err_same' => 'The new password must differ from the username',
            'setup_err_save' => 'Could not save. Make this file writable (644 or 755)',
            'setup_done_already' => 'Setup is already complete; please sign in', 'setup_net' => 'Network error, please retry',
            'setup_app_title' => 'Finish securing your panel', 'setup_app_sub' => 'Set your own account before using the file manager',
            'setup_exit' => 'Sign out', 'setup_show_pass' => 'Show password', 'setup_hide_pass' => 'Hide password',

        ),
        /* 日本語 */
        'ja' => array(
            'brand_sub' => 'シングルファイル・ファイルマネージャー', 'login' => 'ログイン', 'logout' => 'ログアウト', 'user' => 'ユーザー名',
            'pass' => 'パスワード', 'pass_ph' => 'パスワードを入力', 'user_ph' => 'ユーザー名を入力', 'enter' => 'ファイル管理を開く',
            'remember' => 'このデバイスを記憶', 'bad_login' => 'ユーザー名またはパスワードが正しくありません', 'err_net' => '通信エラーです。再試行してください',
            'loading' => '読み込み中…', 'root' => 'ルート', 'files' => 'ファイル', 'recent' => '最近', 'settings' => '設定',
            'all_files' => 'すべてのファイル', 'storage' => 'ストレージ', 'used' => '使用中', 'free' => '空き', 'total' => '合計',
            'search_ph' => 'このフォルダ以下を検索', 'search' => '検索', 'cancel' => 'キャンセル', 'ok' => '決定',
            'new_folder' => '新規フォルダ', 'new_file' => '新規ファイル', 'upload' => 'ファイルをアップロード',
            'upload_folder' => 'フォルダをアップロード', 'url_dl' => 'URL からダウンロード', 'github_dl' => 'GitHub からダウンロード',
            'name' => '名前', 'size' => 'サイズ', 'modified' => '更新日時', 'actions' => '操作', 'type' => '種類', 'path' => 'パス', 'editable' => '編集可', 'previewable' => 'プレビュー可', 'file_kind' => '種類', 'empty' => 'まだ何もありません',
            'empty_sub' => '右下のボタンからアップロードできます', 'rename' => '名前を変更', 'copy' => 'コピー', 'cut' => '切り取り',
            'paste' => '貼り付け', 'delete' => '削除', 'more' => 'その他', 'download' => 'ダウンロード', 'link' => '直リンクをコピー',
            'open' => '開く', 'preview' => 'プレビュー', 'compress' => '圧縮', 'extract' => '解凍', 'info' => '詳細',
            'select' => '選択', 'select_all' => 'すべて選択', 'invert' => '選択を反転', 'none' => '選択を解除', 'selected' => '選択中',
            'items' => '件', 'copied_tip' => 'クリップボードにコピーしました', 'moved_tip' => '移動しました', 'deleted_tip' => '削除しました',
            'saved_tip' => '保存しました', 'paste_here' => 'このフォルダに貼り付け', 'clip_copy' => 'コピー待ち', 'clip_cut' => '移動待ち',
            'clear' => 'クリア', 'editor' => '編集', 'editor_normal' => '標準', 'editor_adv' => '拡張', 'save' => '保存',
            'unsaved' => '未保存の変更があります', 'find' => '検索', 'find_ph' => '検索する文字列', 'replace_ph' => '置換後の文字列',
            'replace' => '置換', 'replace_all' => 'すべて置換', 'ed_busy' => 'ファイルを読み込み中…', 'ed_perf_big' => '大きいファイル',
            'ed_perf_huge' => '巨大ファイル', 'ed_perf_tip' => '性能保護：表示範囲のみを描画します',
            'ed_tip_big' => '大きいファイルのため軽量表示に切り替えました', 'ed_tip_huge' => '巨大ファイルのため標準モードで開き、強調表示を無効にしました',
            'ed_hl_off' => '巨大ファイルのため強調表示を無効にしました', 'ed_paste_big' => '貼り付ける内容が大きいため、一時的に重くなる場合があります。続行しますか？',
            'ed_save_big' => '大きいファイルのため、保存に少し時間がかかります…', 'settings_general' => '一般', 'settings_security' => 'セキュリティ',
            'settings_env' => '環境', 'settings_about' => '情報', 'language' => '言語', 'theme' => 'テーマ',
            'theme_light' => 'ライト', 'theme_dark' => 'ダーク', 'theme_system' => 'システム', 'create' => '新規',
            'new_text' => 'テキストファイルを作成', 'show_hidden' => '隠しファイルを表示', 'show_perms' => '権限と所有者を表示',
            'hide_self' => 'プログラム本体を隠す', 'link_style' => '直リンク形式', 'link_style_pretty' => 'クリーンパス',
            'link_style_param' => '互換パラメータ', 'link_sample_file' => 'ファイル例', 'link_sample_dir' => 'フォルダ例',
            'dir_rule_hint' => 'ファイルの直リンクはサーバーが直接返すため、追加のルールは不要です。https://サイト/フォルダ/ でも開けるようにするには、サイト直下の .htaccess に次のルールを追加してください：',
            'link_style_hint' => 'クリーンパス：ファイルは https://サイト/パス、フォルダは https://サイト/フォルダ/ の形式です（.php やパラメータなし）。フォルダのリンクには、ディレクトリ要求をこのスクリプトへ渡す設定（下の RewriteRule）が必要です。404 になる場合は互換パラメータに切り替えてください',
            'gh_zip_size' => 'Zip サイズ', 'default_editor' => '既定のエディタ', 'change_pass' => 'パスワード変更',
            'old_pass' => '現在のパスワード', 'new_pass' => '新しいパスワード', 'confirm_pass' => '新しいパスワード（確認）',
            'pass_changed' => 'パスワードを更新しました', 'pass_short' => '6 文字以上にしてください',
            'cred_pass_out' => 'パスワードを更新しました。安全のためログアウトしました。', 'cred_user_out' => 'ユーザー名を更新しました。安全のためログアウトしました。',
            'login_again' => '再ログイン', 'pass_mismatch' => 'パスワードが一致しません', 'sign_out' => 'ログアウト',
            'pass_store_hint' => 'パスワードは password_hash（bcrypt）でハッシュ化してこのファイル内に保存され、平文では保存されません。変更後は再ログインが必要です。',
            'env_check' => 'サーバー環境チェック', 'env_recheck' => '再チェック', 'check' => '項目', 'value' => '現在値', 'state' => '状態',
            'good' => '正常', 'warn' => '注意', 'bad' => '異常', 'about_text' => 'PHP 単一ファイルのファイルマネージャー。スマホと PC の両方に対応。',
            'version' => 'バージョン', 'copyright' => '著作権', 'license' => 'ライセンス', 'owner' => '所有者', 'perm' => '権限',
            'url_hint' => '直リンクを貼り付けると、このフォルダに保存します', 'url_ph' => 'https://example.com/file.zip',
            'github_repo' => 'リポジトリ', 'github_ph' => 'owner/repo またはリポジトリ URL', 'github_ref' => 'バージョン / ブランチ',
            'github_load' => 'バージョンを取得', 'github_pick' => 'ダウンロードするバージョンを選択', 'github_default' => '既定のブランチ',
            'github_token' => 'GitHub トークン（任意）', 'github_token_hint' => 'プライベートリポジトリや API 制限の緩和に使用',
            'github_dl_btn' => 'このフォルダにダウンロード', 'github_done' => 'リポジトリをダウンロードしました', 'token_saved' => '設定を保存しました',
            'gh_intro' => 'プロジェクト紹介', 'gh_no_desc' => '説明がありません', 'gh_howto' => 'ダウンロード方法',
            'gh_howto_1' => 'ブランチまたはタグを選ぶと、「設定 · 一般」の方式で zip 保存または解凍します', 'gh_mode' => '保存方法',
            'gh_mode_zip' => 'zip のみ', 'gh_mode_extract' => 'フォルダに解凍', 'gh_will_zip' => '自動解凍なし · {name} として保存',
            'gh_will_extract' => 'フォルダ {name} に解凍', 'gh_saved_zip' => 'zip を保存しました。一覧から解凍できます',
            'github_dl_zip_btn' => 'zip をこのフォルダに保存', 'gh_howto_2' => 'ブランチは最新コミット、タグはリリース済みのスナップショットです',
            'gh_howto_3' => 'プライベートリポジトリは「設定 · 一般」で GitHub トークンを設定してください', 'gh_dl_mode' => 'GitHub の保存方法',
            'gh_dl_mode_hint' => '既定では zip をそのまま保存し、自動解凍しません。解凍を選ぶと同名のフォルダを作成します。', 'gh_change_mode' => '設定で変更',
            'gh_versions' => 'バージョンとブランチ', 'gh_summary' => 'ブランチ {b} 件 · タグ {t} 件', 'gh_latest' => '最新リリース',
            'gh_default_note' => '主開発ライン（通常は最新コード）', 'gh_branch_note' => '開発ブランチ（最新コミットに追従）',
            'gh_tag_note' => 'リリーススナップショット', 'gh_pre' => 'プレリリース', 'gh_sel' => '選択中', 'gh_rel_notes' => 'リリースノート',
            'gh_no_note' => 'このバージョンにリリースノートはありません。該当コミットのスナップショットを取得します', 'gh_view' => 'GitHub で見る',
            'gh_updated' => '更新日', 'gh_forks' => 'Fork', 'gh_archived' => 'アーカイブ済み', 'gh_branches_n' => 'ブランチ',
            'gh_tags_n' => 'タグ', 'rename_to' => '新しい名前', 'folder_name' => 'フォルダ名', 'file_name' => 'ファイル名',
            'zip_format' => '圧縮形式', 'archive_name' => 'アーカイブ名', 'dest_folder' => '保存先フォルダ', 'cmp_title' => 'アーカイブを作成',
            'cmp_create' => '作成', 'cmp_zip_level' => '圧縮レベル', 'cmp_lvl_default' => '既定', 'cmp_lvl_store' => '無圧縮',
            'cmp_lvl_fast' => '高速', 'cmp_lvl_best' => '最小サイズ', 'cmp_copy_after' => '作成後に直リンクをコピー',
            'cmp_save_to' => '保存先', 'cmp_need_name' => 'アーカイブ名を入力してください', 'yes' => '決定', 'no' => 'キャンセル',
            'close' => '閉じる', 'back' => '戻る', 'perm_denied' => '権限がありません', 'not_found' => 'ファイルがありません',
            'copy_ok' => 'コピーしました', 'recent_empty' => '最近使ったファイルはまだありません', 'cut_tip' => '切り取りました。移動先フォルダで貼り付けてください',
            'paste_ok' => '貼り付けました', 'grid' => 'グリッド', 'list' => 'リスト', 'sort' => '並べ替え', 'sort_name' => '名前',
            'sort_size' => 'サイズ', 'sort_time' => '日時', 'sort_type' => '種類', 'asc' => '昇順', 'desc' => '降順',
            'toggle_dir' => '逆順', 'uploading' => 'アップロード中', 'upload_done' => 'アップロード完了',
            'download_start' => 'ダウンロードを開始しました', 'folders' => 'フォルダ', 'images' => '画像', 'videos' => '動画',
            'audios' => '音声', 'docs' => '文書', 'texts' => 'テキスト', 'archives' => 'アーカイブ',
            'no_result' => '一致するファイルがありません', 'try_other' => '別のキーワードをお試しください',
            'delete_confirm' => '削除すると元に戻せません。続行しますか？', 'extract_to' => 'このフォルダにフォルダを作成して解凍',
            'optional' => '空欄なら自動判定', 'extract_title' => 'アーカイブを解凍', 'extract_here' => 'このフォルダに解凍',
            'extract_here_hint' => 'ファイルを直接ここに展開します。同名は自動で改名し、上書きしません', 'extract_folder' => 'フォルダに解凍',
            'extract_folder_hint' => '内容をまとめるフォルダを作成します。名前は変更できます', 'extract_folder_name' => 'フォルダ名',
            'extract_go' => '解凍する', 'undo' => '元に戻す', 'redo' => 'やり直す', 'undo_done' => '元に戻しました',
            'redo_done' => 'やり直しました', 'undo_empty' => '元に戻せる操作はありません', 'redo_empty' => 'やり直せる操作はありません',
            'hist_tip' => '編集履歴 · 最大 80 ステップ', 'no_preview' => 'この形式はオンラインプレビューに対応していません', 'refresh' => '更新',
            'pv_zoom_hint' => 'ピンチで拡大 · ダブルタップで拡大', 'pv_fail_play' => 'このブラウザではこの形式を直接再生できません',
            'pv_fail_image' => 'このブラウザではこの画像形式を表示できません', 'pv_fail_tip' => 'ダウンロードしてローカルのプレーヤーやビューアで開いてください',
            'recent_sub' => '更新日時の順', 'show_hidden_hint' => 'ドットで始まる隠しファイルとフォルダを表示',
            'show_perms_hint' => '一覧と詳細に chmod 権限と所有者を表示', 'hide_self_hint' => '一覧でこのプログラムファイルを隠します（設定はこのファイル内にあります）',
            'two_step_hint' => 'ユーザー名またはパスワードを変更すると即座にログアウトします', 'session_hint' => 'セッションはサーバーに保存されます',
            'sign_out_confirm' => 'ログアウトしますか？', 'close_confirm' => '未保存の変更があります。閉じますか？', 'copying' => 'コピー中',
            'change_user' => 'ユーザー名を変更', 'new_user' => '新しいユーザー名', 'user_changed' => 'ユーザー名を更新しました',
            'backup' => 'バックアップ', 'backup_done' => 'バックアップ完了', 'backup_tip' => 'ファイルと同じ場所に ファイル名-タイムスタンプ.bak を作成します',
            'goto_line' => '行へ移動', 'goto_ph' => '行番号を入力', 'wrap' => '折り返し', 'encoding' => '文字コード',
            'highlight' => '強調表示', 'line_numbers' => '行番号', 'chmod' => '権限を変更', 'chmod_recursive' => 'サブ項目にも適用',
            'chmod_done' => '権限を更新しました', 'move' => '移動', 'move_to' => '移動先', 'move_done' => '移動しました',
            'current' => '現在', 'enc_reload' => '文字コードを切り替えるとファイルを読み直します。未保存の変更は失われます。続行しますか？',
            'file_encoding' => 'ファイルの文字コード', 'enc_tab_save' => '保存時の文字コード', 'enc_tab_read' => '読み直す文字コード',
            'enc_note_save' => '保存時にこの文字コードで書き出します。画面上の文字は変わりません。',
            'enc_note_read' => 'この文字コードで読み直して文字化けを修正します。未保存の変更は失われます。', 'enc_convert_save' => '変換して保存',
            'enc_selected' => '保存時の文字コードを変更しました', 'enc_read_done' => '新しい文字コードで読み直しました', 'enc_default' => '既定',
            'enc_bom_hint' => 'BOM 付き', 'advanced_only' => 'この機能は拡張エディタでのみ使用できます', 'zip_preview' => 'アーカイブの内容',
            'zip_loading' => 'アーカイブを読み込み中…', 'zip_files' => '個のファイル', 'zip_folders' => '個のフォルダ',
            'stat_loading' => '集計中…', 'stat_hint' => 'このフォルダ（サブフォルダを含む）の集計',
            'stat_partial' => 'フォルダが大きすぎるため集計を省略しました',
            'zip_unpacked' => '解凍後', 'zip_ratio' => '圧縮率', 'zip_search_ph' => 'アーカイブ内を検索', 'zip_root' => 'アーカイブ',
            'zip_empty' => 'アーカイブは空です', 'zip_no_match' => '一致するファイルがありません', 'zip_more' => 'さらに読み込む',
            'zip_up' => '上の階層へ', 'zip_exit_search' => '検索を終了してこのフォルダへ戻る', 'zip_truncated' => '項目が多いため先頭 {n} 件のみ表示',
            'zip_back_list' => '一覧に戻る', 'zip_encrypted' => '暗号化', 'zip_entry_dl' => 'このファイルをダウンロード',
            'zip_readonly' => '閲覧のみ。サーバーには解凍しません', 'zip_too_big_hint' => 'ファイルが大きいため、ダウンロードして確認してください',
            'setup_badge' => '初回利用', 'setup_step1' => 'ようこそ', 'setup_step2' => 'アカウント', 'setup_step3' => '完了',
            'setup_hello' => 'まず管理画面に鍵をかけましょう',
            'setup_lead' => '初回起動のため、まだパスワードが設定されていません。30 秒で管理者アカウントを作成し、そのアカウントでログインしてください。',
            'setup_p1' => '既定のパスワードはなく、初回に専用アカウントを作成します', 'setup_p1_hint' => '設定が完了するまで管理画面には入れません',
            'setup_p2' => '設定後は自動的にログインします', 'setup_p3' => 'アカウントとパスワードは「設定 · セキュリティ」で変更できます',
            'setup_start' => 'はじめる', 'setup_title' => '管理者アカウントの作成', 'setup_sub' => 'このアカウントで今後ログインします。大切に保管してください',
            'setup_user_label' => '管理者アカウント', 'setup_user_ph' => '2〜32 文字の英数字または漢字', 'setup_new_label' => '新しいパスワード',
            'setup_new_ph' => '8 文字以上、英字と数字を含む', 'setup_new2_label' => '新しいパスワード（確認）',
            'setup_new2_ph' => 'もう一度入力してください', 'setup_strength' => '強度', 'setup_lv1' => '弱い', 'setup_lv2' => '普通',
            'setup_lv3' => '良い', 'setup_lv4' => '強い', 'setup_rule_len' => '8 文字以上', 'setup_rule_mix' => '英字と数字の両方を含む',
            'setup_rule_weak' => '12345678 などの一般的なパスワードを使わない', 'setup_rule_same' => 'アカウント名と異なる',
            'setup_create' => '作成して進む', 'setup_prev' => '前へ戻る', 'setup_saving' => '保存中…',
            'setup_note' => 'パスワードはハッシュとしてこのファイル内にのみ保存され、平文では保存されません。', 'setup_ok' => '設定完了',
            'setup_ok_sub' => 'アカウントを作成しました。ログインしています…', 'setup_ok_user' => '管理者アカウント', 'setup_enter' => 'ファイル管理を開く',
            'setup_retry' => '入力し直す', 'setup_ok_note' => '安全のためパスワードはここに表示されません。設定したパスワードを忘れないでください。',
            'setup_err_user' => '2〜32 文字の英数字、アンダースコア、ドット、ハイフンまたは漢字を使用してください',
            'setup_err_pass' => '8 文字以上で、英字と数字の両方を含めてください', 'setup_err_weak' => 'このパスワードは一般的すぎます。別のものにしてください',
            'setup_err_pass2' => 'パスワードが一致しません', 'setup_err_same' => '新しいパスワードはアカウント名と異なる必要があります',
            'setup_err_save' => '保存できませんでした。このファイルの書き込み権限（644 または 755）を確認してください',
            'setup_done_already' => '初期設定は完了しています。ログインしてください', 'setup_net' => '通信エラーです。再試行してください',
            'setup_app_title' => 'セキュリティ設定の完了', 'setup_app_sub' => '初回利用時は専用のアカウントを設定してください', 'setup_exit' => 'ログアウト',
            'setup_show_pass' => 'パスワードを表示', 'setup_hide_pass' => 'パスワードを隠す',
        ),
        /* 한국어 */
        'ko' => array(
            'brand_sub' => '단일 파일 파일 관리자', 'login' => '로그인', 'logout' => '로그아웃', 'user' => '사용자 이름', 'pass' => '비밀번호',
            'pass_ph' => '비밀번호를 입력하세요', 'user_ph' => '사용자 이름을 입력하세요', 'enter' => '파일 관리 열기', 'remember' => '이 기기 기억',
            'bad_login' => '사용자 이름 또는 비밀번호가 올바르지 않습니다', 'err_net' => '네트워크 오류입니다. 다시 시도하세요', 'loading' => '불러오는 중…',
            'root' => '루트', 'files' => '파일', 'recent' => '최근', 'settings' => '설정', 'all_files' => '전체 파일',
            'storage' => '저장 공간', 'used' => '사용 중', 'free' => '사용 가능', 'total' => '전체',
            'search_ph' => '현재 폴더 및 하위 폴더 검색', 'search' => '검색', 'cancel' => '취소', 'ok' => '확인',
            'new_folder' => '새 폴더', 'new_file' => '새 파일', 'upload' => '파일 업로드', 'upload_folder' => '폴더 업로드',
            'url_dl' => 'URL 다운로드', 'github_dl' => 'GitHub 다운로드', 'name' => '이름', 'size' => '크기',
            'modified' => '수정 시간', 'actions' => '작업', 'type' => '유형', 'path' => '경로', 'editable' => '편집 가능', 'previewable' => '미리보기', 'file_kind' => '유형', 'empty' => '아직 비어 있습니다', 'empty_sub' => '오른쪽 아래 버튼으로 업로드하세요',
            'rename' => '이름 바꾸기', 'copy' => '복사', 'cut' => '잘라내기', 'paste' => '붙여넣기', 'delete' => '삭제',
            'more' => '더 보기', 'download' => '다운로드', 'link' => '직접 링크 복사', 'open' => '열기', 'preview' => '미리보기',
            'compress' => '압축', 'extract' => '압축 풀기', 'info' => '상세 정보', 'select' => '선택', 'select_all' => '전체 선택',
            'invert' => '선택 반전', 'none' => '선택 해제', 'selected' => '선택됨', 'items' => '개',
            'copied_tip' => '클립보드에 복사했습니다', 'moved_tip' => '이동했습니다', 'deleted_tip' => '삭제했습니다',
            'saved_tip' => '저장했습니다', 'paste_here' => '현재 폴더에 붙여넣기', 'clip_copy' => '복사 대기', 'clip_cut' => '이동 대기',
            'clear' => '지우기', 'editor' => '편집', 'editor_normal' => '일반', 'editor_adv' => '고급', 'save' => '저장',
            'unsaved' => '저장하지 않은 변경이 있습니다', 'find' => '찾기', 'find_ph' => '찾을 내용', 'replace_ph' => '바꿀 내용',
            'replace' => '바꾸기', 'replace_all' => '모두 바꾸기', 'ed_busy' => '파일을 불러오는 중…', 'ed_perf_big' => '큰 파일',
            'ed_perf_huge' => '초대형 파일', 'ed_perf_tip' => '성능 보호: 화면에 보이는 영역만 렌더링합니다',
            'ed_tip_big' => '파일이 커서 경량 렌더링으로 전환했습니다', 'ed_tip_huge' => '파일이 너무 커서 일반 모드로 열고 구문 강조를 껐습니다',
            'ed_hl_off' => '파일이 너무 커서 구문 강조를 껐습니다', 'ed_paste_big' => '붙여넣을 내용이 커서 잠시 느려질 수 있습니다. 계속할까요?',
            'ed_save_big' => '파일이 커서 저장에 시간이 걸립니다…', 'settings_general' => '일반', 'settings_security' => '보안',
            'settings_env' => '환경', 'settings_about' => '정보', 'language' => '언어', 'theme' => '테마',
            'theme_light' => '밝게', 'theme_dark' => '어둡게', 'theme_system' => '시스템', 'create' => '새로 만들기',
            'new_text' => '텍스트 파일 만들기', 'show_hidden' => '숨김 파일 표시', 'show_perms' => '권한 및 소유자 표시',
            'hide_self' => '프로그램 본체 파일 숨기기', 'link_style' => '직접 링크 형식', 'link_style_pretty' => '간단 경로',
            'link_style_param' => '호환 파라미터', 'link_sample_file' => '파일 예시', 'link_sample_dir' => '폴더 예시',
            'dir_rule_hint' => '파일 직접 링크는 서버가 바로 반환하므로 추가 규칙이 필요 없습니다. https://사이트/폴더/ 로도 열리게 하려면 사이트 루트의 .htaccess에 다음 규칙을 추가하세요:',
            'link_style_hint' => '간단 경로: 파일은 https://사이트/파일경로, 폴더는 https://사이트/폴더/ 형식입니다(.php와 파라미터 없음). 폴더 링크는 디렉터리 요청을 이 스크립트로 넘기는 설정(아래 RewriteRule)이 필요하며, 404가 나면 호환 파라미터로 전환하세요',
            'gh_zip_size' => 'Zip 크기', 'default_editor' => '기본 편집기', 'change_pass' => '비밀번호 변경',
            'old_pass' => '현재 비밀번호', 'new_pass' => '새 비밀번호', 'confirm_pass' => '새 비밀번호 확인',
            'pass_changed' => '비밀번호를 변경했습니다', 'pass_short' => '6자 이상이어야 합니다',
            'cred_pass_out' => '비밀번호가 변경되었습니다. 보안을 위해 로그아웃했습니다.',
            'cred_user_out' => '사용자 이름이 변경되었습니다. 보안을 위해 로그아웃했습니다.', 'login_again' => '다시 로그인',
            'pass_mismatch' => '비밀번호가 일치하지 않습니다', 'sign_out' => '로그아웃',
            'pass_store_hint' => '비밀번호는 password_hash(bcrypt)로 해시되어 이 파일에 저장되며 평문으로 저장되지 않습니다. 변경 후 다시 로그인해야 합니다.',
            'env_check' => '서버 환경 점검', 'env_recheck' => '다시 점검', 'check' => '항목', 'value' => '현재 값', 'state' => '상태',
            'good' => '정상', 'warn' => '주의', 'bad' => '오류', 'about_text' => 'PHP 단일 파일 파일 관리자로, 모바일과 PC에 모두 대응합니다.',
            'version' => '버전', 'copyright' => '저작권', 'license' => '라이선스', 'owner' => '소유자', 'perm' => '권한',
            'url_hint' => '직접 링크를 붙여넣으면 현재 폴더에 저장합니다', 'url_ph' => 'https://example.com/file.zip',
            'github_repo' => '저장소', 'github_ph' => 'owner/repo 또는 저장소 URL', 'github_ref' => '버전 / 브랜치',
            'github_load' => '버전 불러오기', 'github_pick' => '다운로드할 버전 선택', 'github_default' => '기본 브랜치',
            'github_token' => 'GitHub 토큰(선택)', 'github_token_hint' => '비공개 저장소 또는 API 호출 제한 완화에 사용',
            'github_dl_btn' => '현재 폴더에 다운로드', 'github_done' => '저장소를 다운로드했습니다', 'token_saved' => '설정을 저장했습니다',
            'gh_intro' => '프로젝트 소개', 'gh_no_desc' => '설명이 없습니다', 'gh_howto' => '다운로드 방법',
            'gh_howto_1' => '브랜치나 태그를 고르면 \'설정 · 일반\'의 방식대로 zip 저장 또는 압축 해제합니다', 'gh_mode' => '저장 방식',
            'gh_mode_zip' => 'zip만', 'gh_mode_extract' => '폴더로 압축 해제', 'gh_will_zip' => '자동 해제 안 함 · {name}으로 저장',
            'gh_will_extract' => '폴더 {name}으로 압축 해제', 'gh_saved_zip' => 'zip을 저장했습니다. 목록에서 압축을 풀 수 있습니다',
            'github_dl_zip_btn' => 'zip을 현재 폴더에 저장', 'gh_howto_2' => '브랜치는 최신 커밋, 태그는 릴리스 스냅샷입니다',
            'gh_howto_3' => '비공개 저장소는 \'설정 · 일반\'에서 GitHub 토큰을 입력하세요', 'gh_dl_mode' => 'GitHub 다운로드 방식',
            'gh_dl_mode_hint' => '기본값은 zip을 그대로 저장하며 자동으로 풀지 않습니다. 압축 해제를 선택하면 같은 이름의 폴더를 만듭니다.',
            'gh_change_mode' => '설정에서 변경', 'gh_versions' => '버전 및 브랜치', 'gh_summary' => '브랜치 {b}개 · 태그 {t}개',
            'gh_latest' => '최신 릴리스', 'gh_default_note' => '주 개발 라인, 보통 최신 코드', 'gh_branch_note' => '개발 브랜치, 최신 커밋 추적',
            'gh_tag_note' => '릴리스 스냅샷', 'gh_pre' => '사전 릴리스', 'gh_sel' => '선택된 버전', 'gh_rel_notes' => '릴리스 노트',
            'gh_no_note' => '이 버전에는 릴리스 노트가 없으며 해당 커밋 스냅샷을 받습니다', 'gh_view' => 'GitHub에서 보기', 'gh_updated' => '업데이트',
            'gh_forks' => 'Fork', 'gh_archived' => '보관됨', 'gh_branches_n' => '브랜치', 'gh_tags_n' => '태그',
            'rename_to' => '새 이름', 'folder_name' => '폴더 이름', 'file_name' => '파일 이름', 'zip_format' => '압축 형식',
            'archive_name' => '압축 파일 이름', 'dest_folder' => '대상 폴더 선택', 'cmp_title' => '압축 파일 만들기',
            'cmp_create' => '만들기', 'cmp_zip_level' => '압축 수준', 'cmp_lvl_default' => '기본', 'cmp_lvl_store' => '무압축',
            'cmp_lvl_fast' => '빠르게', 'cmp_lvl_best' => '최소 크기', 'cmp_copy_after' => '압축 후 직접 링크 복사',
            'cmp_save_to' => '저장 위치', 'cmp_need_name' => '압축 파일 이름을 입력하세요', 'yes' => '확인', 'no' => '취소',
            'close' => '닫기', 'back' => '뒤로', 'perm_denied' => '권한이 없습니다', 'not_found' => '파일이 없습니다',
            'copy_ok' => '복사했습니다', 'recent_empty' => '최근 사용한 파일이 없습니다', 'cut_tip' => '잘라냈습니다. 대상 폴더에서 붙여넣으세요',
            'paste_ok' => '붙여넣었습니다', 'grid' => '격자', 'list' => '목록', 'sort' => '정렬', 'sort_name' => '이름',
            'sort_size' => '크기', 'sort_time' => '시간', 'sort_type' => '종류', 'asc' => '오름차순', 'desc' => '내림차순',
            'toggle_dir' => '방향 전환', 'uploading' => '업로드 중', 'upload_done' => '업로드 완료',
            'download_start' => '다운로드를 시작했습니다', 'folders' => '폴더', 'images' => '이미지', 'videos' => '동영상',
            'audios' => '오디오', 'docs' => '문서', 'texts' => '텍스트', 'archives' => '압축 파일',
            'no_result' => '일치하는 파일이 없습니다', 'try_other' => '다른 검색어를 입력해 보세요',
            'delete_confirm' => '삭제하면 되돌릴 수 없습니다. 계속할까요?', 'extract_to' => '현재 폴더에 폴더를 만들어 압축 해제',
            'optional' => '비우면 자동 인식', 'extract_title' => '압축 풀기', 'extract_here' => '현재 폴더에 풀기',
            'extract_here_hint' => '파일을 현재 위치에 바로 풀고, 이름이 겹치면 자동으로 바꾸며 덮어쓰지 않습니다', 'extract_folder' => '폴더로 풀기',
            'extract_folder_hint' => '내용을 담을 폴더를 만들며 이름을 지정할 수 있습니다', 'extract_folder_name' => '폴더 이름',
            'extract_go' => '압축 풀기', 'undo' => '실행 취소', 'redo' => '다시 실행', 'undo_done' => '실행 취소했습니다',
            'redo_done' => '다시 실행했습니다', 'undo_empty' => '실행 취소할 작업이 없습니다', 'redo_empty' => '다시 실행할 작업이 없습니다',
            'hist_tip' => '편집 기록 · 최대 80단계', 'no_preview' => '이 형식은 온라인 미리보기를 지원하지 않습니다', 'refresh' => '새로 고침',
            'pv_zoom_hint' => '두 손가락으로 확대 · 두 번 탭하여 확대', 'pv_fail_play' => '이 브라우저에서는 이 형식을 바로 재생할 수 없습니다',
            'pv_fail_image' => '이 브라우저에서는 이 이미지 형식을 표시할 수 없습니다', 'pv_fail_tip' => '다운로드한 뒤 로컬 플레이어나 뷰어로 열어 주세요',
            'recent_sub' => '수정 시간 순', 'show_hidden_hint' => '점으로 시작하는 숨김 파일과 폴더 표시',
            'show_perms_hint' => '목록과 상세에 chmod 권한 및 소유자 표시',
            'hide_self_hint' => '목록에서 이 프로그램 파일을 숨깁니다(설정이 이 파일에 포함됨)',
            'two_step_hint' => '사용자 이름이나 비밀번호를 변경하면 즉시 로그아웃됩니다', 'session_hint' => '세션은 서버에 저장됩니다',
            'sign_out_confirm' => '로그아웃할까요?', 'close_confirm' => '저장하지 않은 변경이 있습니다. 닫을까요?', 'copying' => '복사 중',
            'change_user' => '사용자 이름 변경', 'new_user' => '새 사용자 이름', 'user_changed' => '사용자 이름을 변경했습니다',
            'backup' => '백업', 'backup_done' => '백업 완료', 'backup_tip' => '파일이 있는 폴더에 파일명-타임스탬프.bak 백업을 만듭니다',
            'goto_line' => '줄로 이동', 'goto_ph' => '줄 번호 입력', 'wrap' => '자동 줄바꿈', 'encoding' => '인코딩',
            'highlight' => '구문 강조', 'line_numbers' => '줄 번호', 'chmod' => '권한 변경', 'chmod_recursive' => '하위 항목에도 적용',
            'chmod_done' => '권한을 변경했습니다', 'move' => '이동', 'move_to' => '이동 위치', 'move_done' => '이동했습니다',
            'current' => '현재', 'enc_reload' => '인코딩을 바꾸면 파일을 다시 읽습니다. 저장하지 않은 변경은 사라집니다. 계속할까요?',
            'file_encoding' => '파일 인코딩', 'enc_tab_save' => '저장 인코딩', 'enc_tab_read' => '읽기 인코딩',
            'enc_note_save' => '저장할 때 이 인코딩으로 기록하며 화면의 글자는 그대로입니다.',
            'enc_note_read' => '이 인코딩으로 다시 읽어 깨진 글자를 고칩니다. 저장하지 않은 변경은 사라집니다.', 'enc_convert_save' => '변환 후 저장',
            'enc_selected' => '저장 인코딩을 변경했습니다', 'enc_read_done' => '새 인코딩으로 다시 읽었습니다', 'enc_default' => '기본',
            'enc_bom_hint' => 'BOM 포함', 'advanced_only' => '이 기능은 고급 편집기에서만 사용할 수 있습니다',
            'zip_preview' => '압축 파일 내용 보기', 'zip_loading' => '압축 파일을 읽는 중…', 'zip_files' => '개 파일',
            'zip_folders' => '개 폴더', 'zip_unpacked' => '압축 해제 후', 'zip_ratio' => '압축률',
            'stat_loading' => '계산 중…', 'stat_hint' => '이 폴더와 하위 폴더 기준 집계',
            'stat_partial' => '폴더가 너무 커서 집계를 생략했습니다',
            'zip_search_ph' => '압축 파일 내 검색', 'zip_root' => '압축 파일', 'zip_empty' => '압축 파일이 비어 있습니다',
            'zip_no_match' => '일치하는 파일이 없습니다', 'zip_more' => '더 불러오기', 'zip_up' => '상위로',
            'zip_exit_search' => '검색을 종료하고 현재 폴더로', 'zip_truncated' => '항목이 많아 처음 {n}개만 표시합니다',
            'zip_back_list' => '목록으로', 'zip_encrypted' => '암호화됨', 'zip_entry_dl' => '이 파일 다운로드',
            'zip_readonly' => '읽기 전용 미리보기이며 서버에 압축을 풀지 않습니다', 'zip_too_big_hint' => '파일이 커서 다운로드 후 확인하세요',
            'setup_badge' => '첫 사용', 'setup_step1' => '환영합니다', 'setup_step2' => '계정', 'setup_step3' => '완료',
            'setup_hello' => '먼저 관리 화면에 잠금을 걸어 두세요',
            'setup_lead' => '처음 열린 상태이며 아직 비밀번호가 없습니다. 30초 만에 관리자 계정을 만들고 그 계정으로 로그인하세요.',
            'setup_p1' => '기본 비밀번호 없이 첫 사용 시 전용 계정을 만듭니다', 'setup_p1_hint' => '설정을 마칠 때까지 관리 화면에 들어갈 수 없습니다',
            'setup_p2' => '설정 후 자동으로 로그인됩니다', 'setup_p3' => '계정과 비밀번호는 \'설정 · 보안\'에서 언제든 변경할 수 있습니다',
            'setup_start' => '시작하기', 'setup_title' => '관리자 계정 만들기', 'setup_sub' => '이 계정으로 앞으로 로그인합니다. 잘 보관하세요',
            'setup_user_label' => '관리자 계정', 'setup_user_ph' => '2-32자의 영문, 숫자 또는 한자', 'setup_new_label' => '새 비밀번호',
            'setup_new_ph' => '8자 이상, 영문과 숫자 포함', 'setup_new2_label' => '새 비밀번호 확인', 'setup_new2_ph' => '다시 입력하세요',
            'setup_strength' => '강도', 'setup_lv1' => '약함', 'setup_lv2' => '보통', 'setup_lv3' => '좋음',
            'setup_lv4' => '강함', 'setup_rule_len' => '8자 이상', 'setup_rule_mix' => '영문과 숫자를 모두 포함',
            'setup_rule_weak' => '12345678 같은 흔한 비밀번호 사용 안 함', 'setup_rule_same' => '계정 이름과 다르게',
            'setup_create' => '만들고 계속', 'setup_prev' => '이전으로', 'setup_saving' => '저장 중…',
            'setup_note' => '비밀번호는 해시 형태로 이 파일에만 저장되며 평문으로 저장되지 않습니다.', 'setup_ok' => '설정 완료',
            'setup_ok_sub' => '계정을 만들었습니다. 로그인 중…', 'setup_ok_user' => '관리자 계정', 'setup_enter' => '파일 관리 열기',
            'setup_retry' => '다시 입력', 'setup_ok_note' => '보안을 위해 비밀번호는 여기에 표시되지 않습니다. 방금 설정한 비밀번호를 기억하세요.',
            'setup_err_user' => '2-32자의 영문, 숫자, 밑줄, 점, 하이픈 또는 한자를 사용하세요',
            'setup_err_pass' => '8자 이상이며 영문과 숫자를 모두 포함해야 합니다', 'setup_err_weak' => '너무 흔한 비밀번호입니다. 다른 것을 사용하세요',
            'setup_err_pass2' => '비밀번호가 일치하지 않습니다', 'setup_err_same' => '새 비밀번호는 계정 이름과 달라야 합니다',
            'setup_err_save' => '저장하지 못했습니다. 이 파일의 쓰기 권한(644 또는 755)을 확인하세요',
            'setup_done_already' => '초기 설정이 완료되었습니다. 로그인하세요', 'setup_net' => '네트워크 오류입니다. 다시 시도하세요',
            'setup_app_title' => '보안 설정 완료', 'setup_app_sub' => '첫 사용 시 전용 계정을 설정하세요', 'setup_exit' => '로그아웃',
            'setup_show_pass' => '비밀번호 표시', 'setup_hide_pass' => '비밀번호 숨기기',
        ),
        /* Español */
        'es' => array(
            'brand_sub' => 'Gestor de archivos de un solo archivo', 'login' => 'Iniciar sesión',
            'logout' => 'Cerrar sesión', 'user' => 'Usuario', 'pass' => 'Contraseña',
            'pass_ph' => 'Introduce la contraseña', 'user_ph' => 'Introduce el usuario',
            'enter' => 'Abrir el gestor de archivos', 'remember' => 'Recordar este dispositivo',
            'bad_login' => 'Usuario o contraseña incorrectos', 'err_net' => 'Error de red, inténtalo de nuevo',
            'loading' => 'Cargando…', 'root' => 'Raíz', 'files' => 'Archivos', 'recent' => 'Recientes',
            'settings' => 'Ajustes', 'all_files' => 'Todos los archivos', 'storage' => 'Almacenamiento',
            'used' => 'Usado', 'free' => 'Libre', 'total' => 'Total',
            'search_ph' => 'Buscar en esta carpeta y sus subcarpetas', 'search' => 'Buscar', 'cancel' => 'Cancelar',
            'ok' => 'Aceptar', 'new_folder' => 'Nueva carpeta', 'new_file' => 'Nuevo archivo',
            'upload' => 'Subir archivos', 'upload_folder' => 'Subir carpeta', 'url_dl' => 'Descargar desde URL',
            'github_dl' => 'Descargar desde GitHub', 'name' => 'Nombre', 'size' => 'Tamaño',
            'modified' => 'Modificado', 'actions' => 'Acciones', 'type' => 'Tipo', 'path' => 'Ruta', 'editable' => 'Editable', 'previewable' => 'Vista previa', 'file_kind' => 'Tipo', 'empty' => 'Aún no hay nada aquí',
            'empty_sub' => 'Usa el botón inferior derecho para subir', 'rename' => 'Renombrar', 'copy' => 'Copiar',
            'cut' => 'Cortar', 'paste' => 'Pegar', 'delete' => 'Eliminar', 'more' => 'Más', 'download' => 'Descargar',
            'link' => 'Copiar enlace directo', 'open' => 'Abrir', 'preview' => 'Vista previa',
            'compress' => 'Comprimir', 'extract' => 'Extraer', 'info' => 'Detalles', 'select' => 'Seleccionar',
            'select_all' => 'Seleccionar todo', 'invert' => 'Invertir', 'none' => 'No seleccionar',
            'selected' => 'Seleccionado', 'items' => 'elementos', 'copied_tip' => 'Copiado al portapapeles',
            'moved_tip' => 'Movido', 'deleted_tip' => 'Eliminado', 'saved_tip' => 'Guardado',
            'paste_here' => 'Pegar en esta carpeta', 'clip_copy' => 'para copiar', 'clip_cut' => 'para mover',
            'clear' => 'Vaciar', 'editor' => 'Editar', 'editor_normal' => 'Básico', 'editor_adv' => 'Avanzado',
            'save' => 'Guardar', 'unsaved' => 'Hay cambios sin guardar', 'find' => 'Buscar',
            'find_ph' => 'Buscar texto', 'replace_ph' => 'Reemplazar por', 'replace' => 'Reemplazar',
            'replace_all' => 'Reemplazar todo', 'ed_busy' => 'Cargando archivo…', 'ed_perf_big' => 'Archivo grande',
            'ed_perf_huge' => 'Archivo enorme',
            'ed_perf_tip' => 'Protección de rendimiento: solo se dibuja el área visible',
            'ed_tip_big' => 'Archivo grande: se activó el modo ligero',
            'ed_tip_huge' => 'Archivo enorme: abierto en modo básico sin resaltado',
            'ed_hl_off' => 'Archivo enorme: resaltado desactivado',
            'ed_paste_big' => 'El texto pegado es grande y puede ir lento. ¿Continuar?',
            'ed_save_big' => 'Archivo grande: guardar puede tardar un momento…', 'settings_general' => 'General',
            'settings_security' => 'Seguridad', 'settings_env' => 'Entorno', 'settings_about' => 'Acerca de',
            'language' => 'Idioma', 'theme' => 'Tema', 'theme_light' => 'Claro', 'theme_dark' => 'Oscuro',
            'theme_system' => 'Sistema', 'create' => 'Crear', 'new_text' => 'Nuevo archivo de texto',
            'show_hidden' => 'Mostrar archivos ocultos', 'show_perms' => 'Mostrar permisos y propietario',
            'hide_self' => 'Ocultar el archivo del programa', 'link_style' => 'Formato del enlace',
            'link_style_pretty' => 'Ruta limpia', 'link_style_param' => 'Parámetros compatibles',
            'link_sample_file' => 'Ejemplo de archivo', 'link_sample_dir' => 'Ejemplo de carpeta',
            'dir_rule_hint' => 'Los enlaces de archivo los sirve el servidor directamente y no necesitan reglas; para que https://sitio/carpeta/ también abra, añade estas reglas al .htaccess de la raíz:',
            'link_style_hint' => 'Ruta limpia: los archivos son https://sitio/ruta/al/archivo y las carpetas https://sitio/carpeta/ (sin .php ni parámetros). Los enlaces de carpeta necesitan que el servidor envíe las peticiones de directorio a este script (RewriteRule más abajo); si ves un 404, usa Parámetros compatibles',
            'gh_zip_size' => 'Tamaño del zip', 'default_editor' => 'Editor predeterminado',
            'change_pass' => 'Cambiar contraseña', 'old_pass' => 'Contraseña actual',
            'new_pass' => 'Nueva contraseña', 'confirm_pass' => 'Confirmar contraseña',
            'pass_changed' => 'Contraseña actualizada', 'pass_short' => 'Al menos 6 caracteres',
            'cred_pass_out' => 'Contraseña actualizada. Se cerró la sesión por seguridad.',
            'cred_user_out' => 'Usuario actualizado. Se cerró la sesión por seguridad.',
            'login_again' => 'Iniciar sesión de nuevo', 'pass_mismatch' => 'Las contraseñas no coinciden',
            'sign_out' => 'Cerrar sesión',
            'pass_store_hint' => 'La contraseña se guarda con password_hash (bcrypt) dentro de este archivo, nunca en texto plano. Deberás iniciar sesión tras cambiarla.',
            'env_check' => 'Entorno del servidor', 'env_recheck' => 'Volver a comprobar', 'check' => 'Comprobación',
            'value' => 'Valor', 'state' => 'Estado', 'good' => 'Correcto', 'warn' => 'Aviso', 'bad' => 'Error',
            'about_text' => 'Un gestor de archivos PHP de un solo archivo, adaptado a móvil y escritorio.',
            'version' => 'Versión', 'copyright' => 'Copyright', 'license' => 'Licencia', 'owner' => 'Propietario',
            'perm' => 'Permisos', 'url_hint' => 'Pega un enlace directo y el servidor lo guardará en esta carpeta',
            'url_ph' => 'https://example.com/file.zip', 'github_repo' => 'Repositorio',
            'github_ph' => 'owner/repo o URL del repositorio', 'github_ref' => 'Versión / rama',
            'github_load' => 'Cargar versiones', 'github_pick' => 'Elige una versión',
            'github_default' => 'Rama predeterminada', 'github_token' => 'Token de GitHub (opcional)',
            'github_token_hint' => 'Para repositorios privados o más límite de peticiones',
            'github_dl_btn' => 'Descargar en esta carpeta', 'github_done' => 'Repositorio descargado',
            'token_saved' => 'Ajustes guardados', 'gh_intro' => 'Sobre el proyecto',
            'gh_no_desc' => 'Sin descripción', 'gh_howto' => 'Cómo funciona',
            'gh_howto_1' => 'Elige rama o etiqueta; el zip se guarda o se extrae según Ajustes · General',
            'gh_mode' => 'Entrega', 'gh_mode_zip' => 'Solo zip', 'gh_mode_extract' => 'Extraer en carpeta',
            'gh_will_zip' => 'Sin extraer · {name}', 'gh_will_extract' => 'Extraer en {name}',
            'gh_saved_zip' => 'Zip guardado; puedes extraerlo desde la lista',
            'github_dl_zip_btn' => 'Descargar zip aquí',
            'gh_howto_2' => 'Las ramas siguen el último commit; las etiquetas son versiones publicadas',
            'gh_howto_3' => 'Para repos privados añade un token en Ajustes · General',
            'gh_dl_mode' => 'Modo de descarga de GitHub',
            'gh_dl_mode_hint' => 'Por defecto el zip se guarda tal cual, sin extraer. Si eliges extraer se crea una carpeta con el mismo nombre.',
            'gh_change_mode' => 'Cambiar en ajustes', 'gh_versions' => 'Versiones y ramas',
            'gh_summary' => '{b} ramas · {t} etiquetas', 'gh_latest' => 'Última versión',
            'gh_default_note' => 'Línea principal, normalmente el código más reciente',
            'gh_branch_note' => 'Rama de desarrollo, sigue los últimos commits',
            'gh_tag_note' => 'Instantánea de versión', 'gh_pre' => 'Preversión', 'gh_sel' => 'Seleccionada',
            'gh_rel_notes' => 'Notas de la versión',
            'gh_no_note' => 'Esta versión no tiene notas; se descarga la instantánea del commit',
            'gh_view' => 'Ver en GitHub', 'gh_updated' => 'Actualizado', 'gh_forks' => 'Forks',
            'gh_archived' => 'Archivado', 'gh_branches_n' => 'ramas', 'gh_tags_n' => 'etiquetas',
            'rename_to' => 'Nuevo nombre', 'folder_name' => 'Nombre de la carpeta',
            'file_name' => 'Nombre del archivo', 'zip_format' => 'Formato', 'archive_name' => 'Nombre del comprimido',
            'dest_folder' => 'Carpeta de destino', 'cmp_title' => 'Crear comprimido', 'cmp_create' => 'Crear',
            'cmp_zip_level' => 'Compresión', 'cmp_lvl_default' => 'Predeterminada',
            'cmp_lvl_store' => 'Sin comprimir', 'cmp_lvl_fast' => 'Rápida', 'cmp_lvl_best' => 'Tamaño mínimo',
            'cmp_copy_after' => 'Copiar enlace al terminar', 'cmp_save_to' => 'Guardar en',
            'cmp_need_name' => 'Introduce un nombre', 'yes' => 'Aceptar', 'no' => 'Cancelar', 'close' => 'Cerrar',
            'back' => 'Atrás', 'perm_denied' => 'Permiso denegado', 'not_found' => 'Archivo no encontrado',
            'copy_ok' => 'Copiado', 'recent_empty' => 'Aún no hay archivos recientes',
            'cut_tip' => 'Cortado. Abre la carpeta destino y pega', 'paste_ok' => 'Pegado', 'grid' => 'Cuadrícula',
            'list' => 'Lista', 'sort' => 'Ordenar', 'sort_name' => 'Nombre', 'sort_size' => 'Tamaño',
            'sort_time' => 'Fecha', 'sort_type' => 'Tipo', 'asc' => 'Ascendente', 'desc' => 'Descendente',
            'toggle_dir' => 'Invertir', 'uploading' => 'Subiendo', 'upload_done' => 'Subida completada',
            'download_start' => 'Descarga iniciada', 'folders' => 'Carpeta', 'images' => 'Imágenes',
            'videos' => 'Vídeos', 'audios' => 'Audio', 'docs' => 'Documentos', 'texts' => 'Texto',
            'archives' => 'Comprimidos', 'no_result' => 'No hay archivos coincidentes',
            'try_other' => 'Prueba otra palabra', 'delete_confirm' => 'No se puede deshacer. ¿Continuar?',
            'extract_to' => 'Crea una carpeta aquí y extrae dentro',
            'optional' => 'Vacío para detectar automáticamente', 'extract_title' => 'Extraer archivo',
            'extract_here' => 'Extraer en la carpeta actual',
            'extract_here_hint' => 'Los archivos van directamente aquí; los duplicados se renombran y nunca se sobrescriben',
            'extract_folder' => 'Extraer en una carpeta',
            'extract_folder_hint' => 'Crea una carpeta para todo el contenido; el nombre es editable',
            'extract_folder_name' => 'Nombre de la carpeta', 'extract_go' => 'Extraer', 'undo' => 'Deshacer',
            'redo' => 'Rehacer', 'undo_done' => 'Deshecho', 'redo_done' => 'Rehecho',
            'undo_empty' => 'Nada que deshacer', 'redo_empty' => 'Nada que rehacer',
            'hist_tip' => 'Historial de edición · hasta 80 pasos',
            'no_preview' => 'Este formato no admite vista previa', 'refresh' => 'Actualizar',
            'pv_zoom_hint' => 'Pellizca para ampliar · doble toque para agrandar', 'pv_fail_play' => 'Este navegador no puede reproducir este formato',
            'pv_fail_image' => 'Este navegador no puede mostrar este formato de imagen', 'pv_fail_tip' => 'Descárgalo y ábrelo con un reproductor local',
            'recent_sub' => 'Ordenado por fecha de modificación',
            'show_hidden_hint' => 'Muestra archivos y carpetas ocultos',
            'show_perms_hint' => 'Muestra permisos chmod y propietario en la lista y los detalles',
            'hide_self_hint' => 'Oculta este archivo de programa (los ajustes están dentro)',
            'two_step_hint' => 'Al cambiar el usuario o la contraseña se cerrará la sesión',
            'session_hint' => 'La sesión se guarda en el servidor', 'sign_out_confirm' => '¿Cerrar sesión?',
            'close_confirm' => 'Hay cambios sin guardar. ¿Cerrar igual?', 'copying' => 'Copiando',
            'change_user' => 'Cambiar usuario', 'new_user' => 'Nuevo usuario',
            'user_changed' => 'Usuario actualizado', 'backup' => 'Copia de seguridad',
            'backup_done' => 'Copia creada', 'backup_tip' => 'Crea un archivo nombre-fecha.bak junto al original',
            'goto_line' => 'Ir a la línea', 'goto_ph' => 'Número de línea', 'wrap' => 'Ajuste de línea',
            'encoding' => 'Codificación', 'highlight' => 'Resaltado de sintaxis',
            'line_numbers' => 'Números de línea', 'chmod' => 'Cambiar permisos',
            'chmod_recursive' => 'Aplicar a subelementos', 'chmod_done' => 'Permisos actualizados', 'move' => 'Mover',
            'move_to' => 'Mover a', 'move_done' => 'Movido', 'current' => 'Actual',
            'enc_reload' => 'Cambiar la codificación releerá el archivo y perderás los cambios sin guardar. ¿Continuar?',
            'file_encoding' => 'Codificación del archivo', 'enc_tab_save' => 'Al guardar',
            'enc_tab_read' => 'Al releer',
            'enc_note_save' => 'El archivo se escribirá con esta codificación; el texto en pantalla no cambia.',
            'enc_note_read' => 'Relee el archivo con esta codificación para corregir caracteres dañados. Se pierden los cambios sin guardar.',
            'enc_convert_save' => 'Convertir y guardar', 'enc_selected' => 'Codificación de guardado cambiada',
            'enc_read_done' => 'Archivo releído', 'enc_default' => 'Predeterminada', 'enc_bom_hint' => 'con BOM',
            'advanced_only' => 'Esta función solo está disponible en el editor avanzado',
            'zip_preview' => 'Ver contenido del comprimido', 'zip_loading' => 'Leyendo el comprimido…',
            'zip_files' => 'archivos', 'zip_folders' => 'carpetas', 'zip_unpacked' => 'Descomprimido',
            'stat_loading' => 'Calculando…', 'stat_hint' => 'Totales de esta carpeta y sus subcarpetas',
            'stat_partial' => 'Carpeta demasiado grande; recuento truncado',
            'zip_ratio' => 'Compresión', 'zip_search_ph' => 'Buscar dentro del comprimido',
            'zip_root' => 'Comprimido', 'zip_empty' => 'El comprimido está vacío',
            'zip_no_match' => 'No hay archivos coincidentes', 'zip_more' => 'Cargar más',
            'zip_up' => 'Subir un nivel', 'zip_exit_search' => 'Salir de la búsqueda y volver a la carpeta',
            'zip_truncated' => 'Hay muchas entradas; se muestran las primeras {n}',
            'zip_back_list' => 'Volver a la lista', 'zip_encrypted' => 'Cifrado',
            'zip_entry_dl' => 'Descargar este archivo',
            'zip_readonly' => 'Vista previa de solo lectura; no se extrae en el servidor',
            'zip_too_big_hint' => 'El archivo es grande; descárgalo para verlo', 'setup_badge' => 'Primer uso',
            'setup_step1' => 'Bienvenido', 'setup_step2' => 'Cuenta', 'setup_step3' => 'Listo',
            'setup_hello' => 'Protege tu gestor de archivos',
            'setup_lead' => 'Es la primera vez que se abre y aún no hay contraseña. Dedica 30 segundos a crear tu cuenta de administrador y úsala para entrar.',
            'setup_p1' => 'Sin contraseña por defecto; creas tu cuenta en el primer uso',
            'setup_p1_hint' => 'Nadie puede entrar hasta completar la configuración',
            'setup_p2' => 'Iniciarás sesión automáticamente al terminar',
            'setup_p3' => 'Puedes cambiarlos en Ajustes · Seguridad', 'setup_start' => 'Empezar',
            'setup_title' => 'Crea tu cuenta de administrador',
            'setup_sub' => 'Estas credenciales se usarán para iniciar sesión',
            'setup_user_label' => 'Usuario administrador',
            'setup_user_ph' => '2-32 letras, números o caracteres chinos', 'setup_new_label' => 'Nueva contraseña',
            'setup_new_ph' => 'Al menos 8 caracteres con letras y números',
            'setup_new2_label' => 'Confirmar contraseña', 'setup_new2_ph' => 'Repite la contraseña',
            'setup_strength' => 'Seguridad', 'setup_lv1' => 'Débil', 'setup_lv2' => 'Aceptable',
            'setup_lv3' => 'Buena', 'setup_lv4' => 'Fuerte', 'setup_rule_len' => 'Al menos 8 caracteres',
            'setup_rule_mix' => 'Incluye letras y números',
            'setup_rule_weak' => 'No uses contraseñas comunes como 12345678',
            'setup_rule_same' => 'Distinta del usuario', 'setup_create' => 'Crear y continuar',
            'setup_prev' => 'Atrás', 'setup_saving' => 'Guardando…',
            'setup_note' => 'La contraseña se guarda solo como hash dentro de este archivo, nunca en texto plano.',
            'setup_ok' => 'Todo listo', 'setup_ok_sub' => 'Cuenta creada. Iniciando sesión…',
            'setup_ok_user' => 'Usuario administrador', 'setup_enter' => 'Abrir el gestor de archivos',
            'setup_retry' => 'Editar de nuevo',
            'setup_ok_note' => 'Por seguridad la contraseña no se muestra aquí; guárdala bien.',
            'setup_err_user' => 'Usa 2-32 letras, números, guion bajo, punto, guion o caracteres chinos',
            'setup_err_pass' => 'Usa al menos 8 caracteres con letras y números',
            'setup_err_weak' => 'Esa contraseña es demasiado común; elige otra',
            'setup_err_pass2' => 'Las contraseñas no coinciden',
            'setup_err_same' => 'La contraseña debe ser distinta del usuario',
            'setup_err_save' => 'No se pudo guardar. Haz que este archivo sea escribible (644 o 755)',
            'setup_done_already' => 'La configuración ya está completa; inicia sesión',
            'setup_net' => 'Error de red, inténtalo de nuevo', 'setup_app_title' => 'Termina de proteger tu panel',
            'setup_app_sub' => 'Configura tu cuenta antes de usar el gestor', 'setup_exit' => 'Cerrar sesión',
            'setup_show_pass' => 'Mostrar contraseña', 'setup_hide_pass' => 'Ocultar contraseña',
        ),
    );
    return $dict;
}

function current_lang() 
{
    static $lang = null;
    if ($lang !== null) {
        return $lang;
    }
    $candidates = array();
    if (isset($_COOKIE['xiazzi_lang'])) {
        $candidates[] = (string) $_COOKIE['xiazzi_lang'];
    }
    if (isset($_SERVER['HTTP_X_LANG'])) {
        $candidates[] = (string) $_SERVER['HTTP_X_LANG'];
    }
    $s = settings_all();
    if (isset($s['lang'])) {
        $candidates[] = (string) $s['lang'];
    }
    foreach ($candidates as $c) {
        $allDict = i18n_dict();
        if (isset($allDict[$c])) {
            $lang = $c;
            return $lang;
        }
    }
    $lang = 'zh-CN';
    return $lang;
}

function t($key) 
{
    $dict = i18n_dict();
    $lang = current_lang();
    if (isset($dict[$lang][$key])) {
        return $dict[$lang][$key];
    }
    if (isset($dict['en'][$key])) {
        return $dict['en'][$key];
    }
    if (isset($dict['zh-CN'][$key])) {
        return $dict['zh-CN'][$key];
    }
    return $key;
}

/* 直接输出到 HTML 属性的翻译文本（已转义） */
function e_t($key) 
{
    return htmlspecialchars((string) t($key), ENT_QUOTES, 'UTF-8');
}

/* ------------------------ 设置存储（内嵌本体文件） ------------------------ */

function store_defaults() 
{
    return array(
        'v'        => 3,
        'settings' => array(),
        'updated'  => 0,
    );
}

function store_read() 
{
    if (isset($GLOBALS['__xz_store']) && is_array($GLOBALS['__xz_store'])) {
        return $GLOBALS['__xz_store'];
    }
    $store = store_defaults();
    $raw = defined('XIAZZI_STORE') ? trim((string) XIAZZI_STORE) : '';
    if ($raw === '') {
        return $store;
    }
    $json = base64_decode($raw, true);
    if (!is_string($json) || $json === '') {
        return $store;
    }
    $data = json_decode($json, true);
    if (!is_array($data)) {
        return $store;
    }
    if (isset($data['settings']) && is_array($data['settings'])) {
        $store['settings'] = $data['settings'];
    }
    if (isset($data['updated'])) {
        $store['updated'] = (int) $data['updated'];
    }
    if (isset($data['v'])) {
        $store['v'] = (int) $data['v'];
    }
    return $store;
}

/**
 * 把数据写回本体文件：只替换 XIAZZI_STORE 那一行常量。
 * 先写同目录临时文件再 rename，确保任何时刻磁盘上都是一个完整可用的 PHP 文件。
 */
function store_save($store) 
{
    // 版本号只升不降：早期版本此处写死为 2，保存后版本又退回旧值，
    // 下一次请求会重复执行 v3 迁移，把「隐藏程序主体文件」强行改回开启。
    $store['v'] = 3;
    $store['updated'] = time();
    if (!isset($store['settings']) || !is_array($store['settings'])) {
        $store['settings'] = array();
    }
    $json = xz_json_encode($store, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return false;
    }
    $blob = base64_encode($json);

    $src = @file_get_contents(XIAZZI_FILE);
    if (!is_string($src) || $src === '' || strncmp($src, '<?php', 5) !== 0) {
        return false;
    }

    $pattern = "/define\\(\\s*'XIAZZI_STORE'\\s*,\\s*'[A-Za-z0-9+\\/=]*'\\s*\\);/";
    if (!preg_match($pattern, $src)) {
        return false;
    }
    $count = 0;
    // $blob 为 base64，只含 A-Z a-z 0-9 + / =，可安全作为替换串（无 $ 与反斜杠）
    $out = preg_replace($pattern, "define('XIAZZI_STORE', '" . $blob . "');", $src, 1, $count);
    if (!$count || !is_string($out)) {
        return false;
    }
    if ($out === $src) {
        return true; // 数据无变化，不必重写
    }

    // 写回前自检：头部、数据行唯一、结尾标记完好，避免写坏本体文件
    if (strncmp($out, '<?php', 5) !== 0) {
        return false;
    }
    if (preg_match_all("/^define\('XIAZZI_STORE'/m", $out) !== 1) {
        return false;
    }
    if (strpos($out, '</html>') === false) {
        return false;
    }

    $lock = @fopen(XIAZZI_FILE, 'rb');
    if ($lock) {
        @flock($lock, LOCK_EX);
    }

    $ok = false;
    $dir = dirname(XIAZZI_FILE);
    $tmp = $dir . '/.xiazzi-' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $out, LOCK_EX) !== false) {
        /* fileperms 被禁用时这里曾经是致命错误（整个「保存设置 / 修改密码」
           接口 500，权限与拥有者也一并取不到），统一走带开关检测的 stat_bits */
        $keep = stat_bits(XIAZZI_FILE);
        if ($keep['mode'] !== null) {
            @chmod($tmp, (int) $keep['mode'] & 0777);
        }
        $ok = @rename($tmp, XIAZZI_FILE);
        if (!$ok) {
            @unlink($tmp);
        }
    }
    if (!$ok && @is_writable(XIAZZI_FILE)) {
        // 目录不可写时退化为原地写入（文件本身可写即可）
        $ok = (@file_put_contents(XIAZZI_FILE, $out, LOCK_EX) !== false);
    }

    if ($lock) {
        @flock($lock, LOCK_UN);
        @fclose($lock);
    }
    if ($ok && function_exists('opcache_invalidate')) {
        @opcache_invalidate(XIAZZI_FILE, true);
    }
    if ($ok) {
        $GLOBALS['__xz_store'] = $store; // 同一请求内后续读写以内存中的新值为准
    }
    return (bool) $ok;
}

function store_patch($patch) 
{
    $store = store_read();
    foreach ($patch as $k => $v) {
        $store[$k] = $v;
    }
    return store_save($store);
}

function settings_defaults() 
{
    return array(
        'lang'            => 'zh-CN',
        'theme'           => 'system',
        'show_hidden'     => false,
        'show_perms'      => false,
        'hide_self'       => true,
        'editor'          => 'normal',
        'last_dir'        => '',
        'gh_token'        => '',
        'gh_extract'      => false,
        'link_style'      => 'pretty',
        'user'            => '',
        'pass_hash'       => '',
        'remember_secret' => '',
        'setup_done'      => false,
        'setup_at'        => 0,
    );
}

function settings_all() 
{
    if (isset($GLOBALS['__xz_settings']) && is_array($GLOBALS['__xz_settings'])) {
        return $GLOBALS['__xz_settings'];
    }
    $cache = settings_defaults();
    $store = store_read();
    // 设置只来自本文件内嵌的数据行，不再读取任何外置文件
    $source = isset($store['settings']) && is_array($store['settings']) ? $store['settings'] : array();

    foreach ($source as $k => $v) {
        if (array_key_exists($k, $cache)) {
            $cache[$k] = $v;
        }
    }

    // v3：程序主体文件默认隐藏。仅在旧版升级、且从未保存过该开关时切换一次，
    // 之后完全以用户开关为准（版本号持久化为 3，不会再被反复覆盖）。
    $ver = isset($store['v']) ? (int) $store['v'] : 2;
    if ($ver < 3) {
        if (!array_key_exists('hide_self', $source)) {
            $cache['hide_self'] = true;
        }
        $store['v'] = 3;
        $store['settings'] = $cache;
        store_save($store);
    }

    $GLOBALS['__xz_settings'] = $cache;
    return $cache;
}

function settings_write($patch) 
{
    $data = settings_all();
    foreach ($patch as $k => $v) {
        $data[$k] = $v;
    }
    if (!store_patch(array('settings' => $data))) {
        return false;
    }
    $GLOBALS['__xz_settings'] = $data;
    return true;
}

function setting($key,  $default = null) 
{
    $s = settings_all();
    return array_key_exists($key, $s) ? $s[$key] : $default;
}

function secret() 
{
    $s = settings_all();
    if (!empty($s['remember_secret']) && strlen((string) $s['remember_secret']) >= 32) {
        return (string) $s['remember_secret'];
    }
    $new = bin2hex(random_bytes(24));
    @settings_write(array('remember_secret' => $new));
    return $new;
}

function effective_user() 
{
    $s = settings_all();
    if (!empty($s['user'])) {
        return (string) $s['user'];
    }
    global $CONFIG;
    return (string) $CONFIG['user'];
}

/* 当前生效的密码哈希：只取自内嵌设置，程序不内置任何默认密码。
 * 哈希为空表示尚未完成首次设置，此时不允许登录。
 * 全流程只操作哈希，配置文件与设置数据中都不存在明文密码。 */
function stored_pass_hash() 
{
    $s = settings_all();
    if (!empty($s['pass_hash'])) {
        return (string) $s['pass_hash'];
    }
    return '';
}

function verify_password($pass) 
{
    $hash = stored_pass_hash();
    if ($hash === '') {
        return false;
    }
    if (!password_verify((string) $pass, $hash)) {
        return false;
    }
    // 极老环境遗留的加盐 SHA-256 摘要：校验通过后自动升级为 password_hash 哈希
    if (strpos($hash, 'sha256:') === 0 && defined('CRYPT_BLOWFISH') && CRYPT_BLOWFISH == 1) {
        @settings_write(array('pass_hash' => password_hash((string) $pass, PASSWORD_DEFAULT)));
    }
    return true;
}

/* 是否还需要首次使用引导：
 * 程序没有默认密码，只要设置里还没有密码哈希，就必须先完成首次设置。
 * 已设置过密码的部署不会被打扰。 */
function setup_required() 
{
    if (!auth_enabled()) {
        return false;
    }
    return stored_pass_hash() === '';
}

/* 密码强度评分 0-4：长度、大小写/数字组合、符号。前后端使用同一规则。 */
function password_score($pass) 
{
    $pass = (string) $pass;
    $len = strlen($pass);
    $score = 0;
    if ($len >= 8) {
        $score++;
    }
    if ($len >= 12) {
        $score++;
    }
    if (preg_match('/[A-Za-z]/', $pass) && preg_match('/[0-9]/', $pass)) {
        $score++;
    }
    if (preg_match('/[^A-Za-z0-9]/', $pass)) {
        $score++;
    }
    return $score > 4 ? 4 : $score;
}

/* 常见弱密码（不区分大小写） */
function is_weak_password($pass) 
{
    $list = array('admin123', 'admin888', '12345678', '123456789', '11111111',
        'password', 'password1', 'qwerty123', 'abc123456', 'adminadmin');
    return in_array(strtolower((string) $pass), $list, true);
}

/* 校验新密码：至少 8 位、同时包含字母与数字、不能是常见弱密码 */
function check_new_password($pass, $user) 
{
    $pass = (string) $pass;
    if (strlen($pass) < 8) {
        api_fail(t('setup_err_pass'), 400);
    }
    if (strlen($pass) > 200) {
        api_fail('密码过长', 400);
    }
    if (!preg_match('/[A-Za-z]/', $pass) || !preg_match('/[0-9]/', $pass)) {
        api_fail(t('setup_err_pass'), 400);
    }
    if (is_weak_password($pass)) {
        api_fail(t('setup_err_weak'), 400);
    }
    if ($user !== '' && strtolower($pass) === strtolower((string) $user)) {
        api_fail(t('setup_err_same'), 400);
    }
}

/* 校验管理员账号：2-32 位字母、数字、下划线、点、短横线或汉字 */
function check_admin_user($user) 
{
    if (!preg_match('/^[A-Za-z0-9_.\-\x{4e00}-\x{9fa5}]{2,32}$/u', (string) $user)) {
        api_fail(t('setup_err_user'), 400);
    }
}

/* 建立登录态：重建会话 ID、写入新 CSRF、按需签发记住登录令牌 */
function begin_login_session($user, $remember) 
{
    if (function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE) {
        @session_regenerate_id(true);
    }
    $_SESSION = array();
    $_SESSION['tfm_user'] = (string) $user;
    $_SESSION['login_fails'] = 0;
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
    if ($remember) {
        issue_remember_cookie((string) $user);
    }
    return $_SESSION['csrf'];
}

/* ------------------------------ 基础工具 ------------------------------ */

class ApiException extends Exception
{
}

function api_fail($message,  $code = 400) 
{
    throw new ApiException($message, $code);
}

function json_out($payload,  $code = 200) 
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $body = xz_json_encode($payload, $flags);
    echo $body === false ? '{"ok":false,"error":"encode error"}' : $body;
    exit;
}

function request_data() 
{
    static $data = null;
    if ($data !== null) {
        return $data;
    }
    $data = array();
    $raw = file_get_contents('php://input');
    if (is_string($raw) && $raw !== '') {
        $type = isset($_SERVER['CONTENT_TYPE']) ? strtolower((string) $_SERVER['CONTENT_TYPE']) : '';
        if (strpos($type, 'application/json') !== false) {
            $parsed = json_decode($raw, true);
            if (is_array($parsed)) {
                $data = $parsed;
            }
        } else {
            parse_str($raw, $parsed);
            if (is_array($parsed)) {
                $data = $parsed;
            }
        }
    }
    foreach ($_GET as $k => $v) {
        if (!array_key_exists($k, $data)) {
            $data[$k] = $v;
        }
    }
    foreach ($_POST as $k => $v) {
        $data[$k] = $v;
    }
    return $data;
}

function param($key,  $default = null) 
{
    $data = request_data();
    return array_key_exists($key, $data) ? $data[$key] : $default;
}

function root_dir() 
{
    global $CONFIG;
    $root = (string) $CONFIG['root'];
    $real = realpath($root);
    if ($real === false) {
        $real = realpath(XIAZZI_DIR);
    }
    $real = str_replace('\\', '/', (string) $real);
    return rtrim($real, '/') === '' ? '/' : rtrim($real, '/');
}

function rel_path($abs) 
{
    $root = root_dir();
    $abs = str_replace('\\', '/', $abs);
    if ($abs === $root) {
        return '';
    }
    if ($root === '/') {
        return ltrim($abs, '/');
    }
    if (strpos($abs, $root . '/') === 0) {
        return substr($abs, strlen($root) + 1);
    }
    return '';
}

function join_rel($rel) 
{
    $root = root_dir();
    $rel = trim(str_replace('\\', '/', $rel), '/');
    if ($rel === '') {
        return $root;
    }
    return ($root === '/' ? '' : $root) . '/' . $rel;
}

function resolve_path($rel,  $mustExist = true) 
{
    $rel = str_replace('\\', '/', $rel);
    if (strpos($rel, "\0") !== false) {
        api_fail('路径包含非法字符');
    }
    $rel = preg_replace('#/+#', '/', $rel);
    $rel = ltrim((string) $rel, '/');
    $abs = join_rel($rel);
    $real = realpath($abs);
    if ($real === false) {
        if ($mustExist) {
            api_fail(t('not_found'), 404);
        }
        $parent = realpath(dirname($abs));
        if ($parent === false) {
            api_fail(t('not_found'), 404);
        }
        $parent = str_replace('\\', '/', $parent);
        $root = root_dir();
        if ($parent !== $root && strpos($parent . '/', $root . '/') !== 0) {
            api_fail(t('perm_denied'), 403);
        }
        return $parent . '/' . basename($abs);
    }
    $real = str_replace('\\', '/', $real);
    $root = root_dir();
    if ($real !== $root && strpos($real . '/', $root . '/') !== 0) {
        api_fail(t('perm_denied'), 403);
    }
    return $real;
}

function check_name($name) 
{
    $name = trim(str_replace(array('/', '\\'), '', $name));
    if ($name === '' || $name === '.' || $name === '..') {
        api_fail('名称不能为空');
    }
    if (preg_match('/[<>:"|?*\x00-\x1f]/', $name)) {
        api_fail('名称包含非法字符');
    }
    if (strlen($name) > 200) {
        api_fail('名称过长');
    }
    return $name;
}

function ext_of($name) 
{
    $lower = strtolower($name);
    if (substr($lower, -7) === '.tar.gz') {
        return 'tar.gz';
    }
    $pos = strrpos($lower, '.');
    if ($pos === false || $pos === 0) {
        return '';
    }
    return substr($lower, $pos + 1);
}

function blocked_ext($name) 
{
    global $CONFIG;
    // 默认不限制任何上传 / 新建格式；如需恢复限制，把 $CONFIG['restrict_ext'] 改为 true
    if (empty($CONFIG['restrict_ext'])) {
        return false;
    }
    $ext = ext_of($name);
    return $ext !== '' && in_array($ext, $CONFIG['block_ext'], true);
}

function kind_of($name,  $isDir = false) 
{
    if ($isDir) {
        return 'folder';
    }
    $ext = ext_of($name);
    $map = array(
        'image' => array('jpg', 'jpeg', 'jpe', 'jfif', 'pjpeg', 'png', 'apng', 'gif', 'webp', 'bmp', 'dib', 'svg', 'svgz',
                         'ico', 'cur', 'avif', 'heic', 'heif', 'tif', 'tiff', 'jxl', 'psd', 'exr', 'hdr',
                         'raw', 'cr2', 'cr3', 'nef', 'arw', 'dng', 'orf', 'rw2', 'raf', 'sr2'),
        'video' => array('mp4', 'm4v', 'webm', 'mov', 'qt', 'mkv', 'avi', 'ogv', 'flv', 'f4v', 'wmv', 'asf',
                         '3gp', '3g2', 'mpg', 'mpeg', 'mpe', 'm1v', 'm2v', 'm2ts', 'mts', 'm3u8', 'm3u',
                         'rm', 'rmvb', 'divx', 'vob', 'ogm', 'dv', 'h264', 'h265', 'hevc'),
        'audio' => array('mp3', 'mp2', 'mpga', 'wav', 'wave', 'ogg', 'oga', 'opus', 'flac', 'm4a', 'm4b', 'aac',
                         'weba', 'wma', 'ape', 'amr', 'aiff', 'aif', 'aifc', 'au', 'snd', 'mid', 'midi', 'mka',
                         'ac3', 'dts', 'tak', 'wv', 'tta', 'alac', 'dsf', 'dff', 'ra', 'caf', '3ga'),
        'text'  => array('txt', 'md', 'markdown', 'json', 'js', 'mjs', 'ts', 'tsx', 'jsx', 'css', 'scss', 'less', 'html', 'htm', 'xml', 'yml', 'yaml', 'ini', 'conf', 'env', 'log', 'csv', 'sql', 'svg', 'gitignore', 'php', 'py', 'sh', 'java', 'c', 'h', 'cpp', 'go', 'rb', 'rs', 'vue', 'lock', 'toml'),
        'archive' => array('zip', 'tar', 'gz', 'tgz', 'rar', '7z', 'bz2', 'xz'),
        'doc'   => array('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'epub'),
    );
    foreach ($map as $kind => $exts) {
        if (in_array($ext, $exts, true)) {
            return $kind;
        }
    }
    return 'file';
}

function mime_of($ext) 
{
    $map = array(
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif',
        'webp' => 'image/webp', 'bmp' => 'image/bmp', 'svg' => 'image/svg+xml', 'ico' => 'image/x-icon',
        'jpe' => 'image/jpeg', 'jfif' => 'image/jpeg', 'pjpeg' => 'image/jpeg', 'apng' => 'image/apng',
        'heic' => 'image/heic', 'heif' => 'image/heif', 'tif' => 'image/tiff', 'tiff' => 'image/tiff',
        'jxl' => 'image/jxl', 'psd' => 'image/vnd.adobe.photoshop', 'cur' => 'image/x-icon',
        'avif' => 'image/avif', 'mp4' => 'video/mp4', 'm4v' => 'video/x-m4v', 'webm' => 'video/webm',
        'mov' => 'video/quicktime', 'qt' => 'video/quicktime', 'mkv' => 'video/x-matroska', 'avi' => 'video/x-msvideo',
        'ogv' => 'video/ogg', 'flv' => 'video/x-flv', 'f4v' => 'video/x-f4v', 'wmv' => 'video/x-ms-wmv',
        'asf' => 'video/x-ms-asf', '3gp' => 'video/3gpp', '3g2' => 'video/3gpp2', 'mpg' => 'video/mpeg',
        'mpeg' => 'video/mpeg', 'mpe' => 'video/mpeg', 'm2v' => 'video/mpeg', 'm1v' => 'video/mpeg',
        'm2ts' => 'video/mp2t', 'mts' => 'video/mp2t', 'ts' => 'video/mp2t',
        'm3u8' => 'application/vnd.apple.mpegurl', 'm3u' => 'audio/x-mpegurl',
        'rm' => 'application/vnd.rn-realmedia', 'rmvb' => 'application/vnd.rn-realmedia-vbr',
        'divx' => 'video/divx', 'vob' => 'video/dvd', 'ogm' => 'video/ogg', 'dv' => 'video/dv',
        'mp3' => 'audio/mpeg', 'mp2' => 'audio/mpeg', 'mpga' => 'audio/mpeg', 'wav' => 'audio/wav',
        'wave' => 'audio/wav', 'ogg' => 'audio/ogg', 'oga' => 'audio/ogg', 'opus' => 'audio/ogg',
        'flac' => 'audio/flac', 'm4a' => 'audio/mp4', 'm4b' => 'audio/mp4', 'aac' => 'audio/aac',
        'weba' => 'audio/webm', 'wma' => 'audio/x-ms-wma', 'ape' => 'audio/x-ape', 'amr' => 'audio/amr',
        'aiff' => 'audio/aiff', 'aif' => 'audio/aiff', 'aifc' => 'audio/aiff', 'au' => 'audio/basic',
        'snd' => 'audio/basic', 'mid' => 'audio/midi', 'midi' => 'audio/midi', 'mka' => 'audio/x-matroska',
        'ac3' => 'audio/ac3', 'dts' => 'audio/vnd.dts', 'wv' => 'audio/x-wavpack', 'tta' => 'audio/x-tta',
        'alac' => 'audio/mp4', 'dsf' => 'audio/x-dsf', 'dff' => 'audio/x-dff', 'ra' => 'audio/x-realaudio',
        'caf' => 'audio/x-caf', '3ga' => 'audio/3gpp',
        'pdf' => 'application/pdf', 'json' => 'application/json',
        'js' => 'application/javascript', 'mjs' => 'application/javascript', 'css' => 'text/css',
        'html' => 'text/html', 'htm' => 'text/html', 'xml' => 'application/xml', 'txt' => 'text/plain',
        'md' => 'text/markdown', 'csv' => 'text/csv', 'zip' => 'application/zip', 'tar' => 'application/x-tar',
        'gz' => 'application/gzip', 'tar.gz' => 'application/gzip', 'woff' => 'font/woff', 'woff2' => 'font/woff2',
        'ttf' => 'font/ttf', 'otf' => 'font/otf', 'wasm' => 'application/wasm',
    );
    return isset($map[$ext]) ? $map[$ext] : 'application/octet-stream';
}

function human_size($bytes) 
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    $units = array('KB', 'MB', 'GB', 'TB');
    $value = (float) $bytes;
    foreach ($units as $unit) {
        $value /= 1024;
        if ($value < 1024) {
            return ($value >= 100 ? number_format($value, 0) : number_format($value, 1)) . ' ' . $unit;
        }
    }
    return number_format($value, 1) . ' PB';
}

/* ---------------------- 权限与拥有者（受限环境兼容层） ----------------------
 * 免费空间常把 fileperms / fileowner / filegroup / posix_getpwuid 等函数列入
 * disable_functions。早期实现只认这几个函数，取不到就直接返回空串，于是「详细信
 * 息」里的权限和拥有者始终为空。下面统一按 stat() -> 同名函数 -> 系统账号库的顺序
 * 逐级回退，只要任何一档可用就能拿到结果。
 */
function is_link_path($path) 
{
    if (!xz_fn_ok('is_link')) {
        return false;
    }
    return (bool) @is_link($path);
}

function stat_bits($path, $follow = true) 
{
    static $cache = array();
    $key = (string) $path . '|' . ($follow ? 'f' : 'l');
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $row = array('mode' => null, 'uid' => null, 'gid' => null);
    $st = false;
    if ($follow) {
        if (xz_fn_ok('stat')) {
            $st = @stat($path);
        }
    } else {
        if (xz_fn_ok('lstat')) {
            $st = @lstat($path);
        } elseif (xz_fn_ok('stat')) {
            $st = @stat($path);
        }
    }
    if (is_array($st)) {
        if (isset($st['mode'])) { $row['mode'] = (int) $st['mode']; }
        if (isset($st['uid'])) { $row['uid'] = (int) $st['uid']; }
        if (isset($st['gid'])) { $row['gid'] = (int) $st['gid']; }
    }
    if ($row['mode'] === null && xz_fn_ok('fileperms')) {
        $pm = @fileperms($path);
        if (is_int($pm)) { $row['mode'] = $pm; }
    }
    if ($row['uid'] === null && xz_fn_ok('fileowner')) {
        $ow = @fileowner($path);
        if (is_int($ow)) { $row['uid'] = $ow; }
    }
    if ($row['gid'] === null && xz_fn_ok('filegroup')) {
        $gr = @filegroup($path);
        if (is_int($gr)) { $row['gid'] = $gr; }
    }
    $cache[$key] = $row;
    return $row;
}

/* 八进制权限：常规为三位（644 / 755），带特殊位时为四位（4755 / 2755）。
   早期写法取 mode 末四位，普通文件会被显示成 0644。 */
function perm_octal($mode) 
{
    if ($mode === null) {
        return '';
    }
    return sprintf('%o', ((int) $mode) & 07777);
}

/* 符号形式 drwxr-xr-x / -rw-r--r--，与 ls -l 的权限列一致 */
function perm_symbolic($mode, $isDir) 
{
    if ($mode === null) {
        return '';
    }
    $mode = (int) $mode;
    if ($isDir) {
        $head = 'd';
    } else {
        $kind = $mode & 0170000;
        if ($kind === 0120000) { $head = 'l'; }
        elseif ($kind === 0010000) { $head = 'p'; }
        elseif ($kind === 0020000) { $head = 'c'; }
        elseif ($kind === 0060000) { $head = 'b'; }
        elseif ($kind === 0140000) { $head = 's'; }
        else { $head = '-'; }
    }
    $rwx = '';
    for ($i = 0; $i < 3; $i++) {
        $seg = ($mode >> (6 - 3 * $i)) & 7;
        $rwx .= (($seg & 4) ? 'r' : '-') . (($seg & 2) ? 'w' : '-') . (($seg & 1) ? 'x' : '-');
    }
    if ($mode & 04000) {
        $rwx = substr_replace($rwx, (($mode & 0100) ? 's' : 'S'), 2, 1);
    }
    if ($mode & 02000) {
        $rwx = substr_replace($rwx, (($mode & 0010) ? 's' : 'S'), 5, 1);
    }
    if ($mode & 01000) {
        $rwx = substr_replace($rwx, (($mode & 0001) ? 't' : 'T'), 8, 1);
    }
    return $head . $rwx;
}

/* UID / GID 转名称：posix_* 不可用时读系统账号库，每个请求只解析一次 */
function id_name_map($file, $idIndex) 
{
    static $cache = array();
    $key = (string) $file;
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $map = array();
    if ($idIndex > 0 && @is_readable($file) && xz_fn_ok('file_get_contents')) {
        $txt = @file_get_contents($file);
        if (is_string($txt) && $txt !== '') {
            foreach (explode("\n", $txt) as $line) {
                $p = explode(':', $line);
                if (count($p) > $idIndex && $p[$idIndex] !== '' && ctype_digit($p[$idIndex])) {
                    $map[(int) $p[$idIndex]] = (string) $p[0];
                }
            }
        }
    }
    $cache[$key] = $map;
    return $map;
}

function user_name_of_id($uid) 
{
    $uid = (int) $uid;
    if (xz_fn_ok('posix_getpwuid')) {
        $info = @posix_getpwuid($uid);
        if (is_array($info) && isset($info['name']) && $info['name'] !== '') {
            return (string) $info['name'];
        }
    }
    $map = id_name_map('/etc/passwd', 2);
    if (isset($map[$uid])) {
        return $map[$uid];
    }
    return '';
}

function group_name_of_id($gid) 
{
    $gid = (int) $gid;
    if (xz_fn_ok('posix_getgrgid')) {
        $info = @posix_getgrgid($gid);
        if (is_array($info) && isset($info['name']) && $info['name'] !== '') {
            return (string) $info['name'];
        }
    }
    $map = id_name_map('/etc/group', 2);
    if (isset($map[$gid])) {
        return $map[$gid];
    }
    return '';
}

function file_owner_name($path) 
{
    $row = stat_bits($path);
    if ($row['uid'] === null) {
        return '';
    }
    $name = user_name_of_id($row['uid']);
    if ($name !== '') {
        return $name;
    }
    if ((int) $row['uid'] === 0) {
        return 'root';
    }
    return (string) $row['uid'];
}

function file_group_name($path) 
{
    $row = stat_bits($path);
    if ($row['gid'] === null) {
        return '';
    }
    $name = group_name_of_id($row['gid']);
    if ($name !== '') {
        return $name;
    }
    if ((int) $row['gid'] === 0) {
        return 'root';
    }
    return (string) $row['gid'];
}

function item_of($abs,  $extra = array(), $rawAbs = null) 
{
    $isDir = is_dir($abs);
    /* 详情接口传进来的往往是 realpath 之后的目标路径，符号链接本身的信息放在
       $rawAbs 里，取权限与拥有者时以它为准，与列表口径保持一致 */
    $probe = ($rawAbs === null || $rawAbs === '') ? $abs : (string) $rawAbs;
    $isLink = is_link_path($probe);
    $name = basename($abs);
    $size = $isDir ? 0 : (int) @filesize($abs);
    $mtime = (int) @filemtime($abs);
    $rel = rel_path($abs);
    $item = array(
        'name'  => $name,
        'path'  => $rel,
        'dir'   => $isDir,
        'size'  => $size,
        'sizeText' => $isDir ? '' : human_size($size),
        'mtime' => $mtime,
        'ext'   => $isDir ? '' : ext_of($name),
        'kind'  => kind_of($name, $isDir),
    );
    if (!empty($extra['perms'])) {
        $statRow = stat_bits($probe, !$isLink);
        $item['perm'] = perm_octal($statRow['mode']);
        $item['permText'] = perm_symbolic($statRow['mode'], $isDir);
        $item['owner'] = file_owner_name($abs);
        $item['group'] = file_group_name($abs);
    }
    /* perms 只是内部开关，不要混进返回给前端的 JSON */
    unset($extra['perms']);
    return array_merge($item, $extra);
}

function unique_path($dir,  $name) 
{
    $target = rtrim($dir, '/') . '/' . $name;
    if (!file_exists($target)) {
        return $target;
    }
    $info = pathinfo($name);
    $base = isset($info['filename']) ? $info['filename'] : $name;
    $ext = isset($info['extension']) && $info['extension'] !== '' ? '.' . $info['extension'] : '';
    if (ext_of($name) === 'tar.gz') {
        $base = substr($name, 0, -7);
        $ext = '.tar.gz';
    }
    for ($i = 2; $i < 9999; $i++) {
        $candidate = rtrim($dir, '/') . '/' . $base . ' (' . $i . ')' . $ext;
        if (!file_exists($candidate)) {
            return $candidate;
        }
    }
    return rtrim($dir, '/') . '/' . $base . '-' . time() . $ext;
}

function remove_recursive($path) 
{
    if (is_link($path) || is_file($path)) {
        return @unlink($path);
    }
    if (!is_dir($path)) {
        return false;
    }
    $names = @scandir($path);
    if ($names === false) {
        return false;
    }
    foreach ($names as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        if (!remove_recursive($path . '/' . $name)) {
            return false;
        }
    }
    return @rmdir($path);
}

function copy_recursive($src,  $dst) 
{
    if (is_link($src) || is_file($src)) {
        return @copy($src, $dst);
    }
    if (!is_dir($src)) {
        return false;
    }
    if (!@mkdir($dst, 0755) && !is_dir($dst)) {
        return false;
    }
    $names = @scandir($src);
    if ($names === false) {
        return false;
    }
    foreach ($names as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        if (!copy_recursive($src . '/' . $name, $dst . '/' . $name)) {
            return false;
        }
    }
    return true;
}

function hidden_name($name) 
{
    return isset($name[0]) && $name[0] === '.';
}

function self_files() 
{
    // 只有本体文件：设置已内嵌其中，不再有外置配置文件
    return array(basename(XIAZZI_FILE));
}

function visible_name($name) 
{
    if (setting('hide_self', true) && in_array($name, self_files(), true)) {
        return false;
    }
    if (hidden_name($name) && !setting('show_hidden', false)) {
        return false;
    }
    return true;
}

/* 排序回调（PHP 5.2 无闭包，统一用命名函数） */
function cmp_item_name($a, $b)
{
    if ($a['dir'] !== $b['dir']) {
        return $a['dir'] ? -1 : 1;
    }
    return strcasecmp($a['name'], $b['name']);
}

function cmp_mtime_desc($a, $b)
{
    if ($b['mtime'] == $a['mtime']) {
        return 0;
    }
    return $b['mtime'] > $a['mtime'] ? -1 : 1;
}

function list_items($rel) 
{
    $dir = resolve_path($rel);
    if (!is_dir($dir)) {
        api_fail('不是文件夹');
    }
    $names = @scandir($dir);
    if ($names === false) {
        api_fail(t('perm_denied'), 403);
    }
    $showPerms = (bool) setting('show_perms', false);
    $items = array();
    foreach ($names as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        if (!visible_name($name)) {
            continue;
        }
        $items[] = item_of($dir . '/' . $name, array('perms' => $showPerms));
    }
    usort($items, 'cmp_item_name');
    return $items;
}

/* 递归统计一个目录（绝对路径）：文件数、文件夹数与文件总大小
   有扫描上限与时间上限，目录过大时返回 partial = 1，避免拖慢请求 */
function dir_stats_abs($dir)
{
    $files = 0;
    $dirs = 0;
    $size = 0;
    $partial = 0;
    $maxEntries = 50000;
    $deadline = microtime(true) + 2.5;
    $stack = array($dir);
    $seen = 0;
    while ($stack) {
        $current = array_pop($stack);
        $names = @scandir($current);
        if ($names === false) {
            continue;
        }
        foreach ($names as $name) {
            if ($name === '.' || $name === '..' || !visible_name($name)) {
                continue;
            }
            $abs = $current . '/' . $name;
            $seen++;
            if (is_link($abs)) {
                $files++;
                $sz = @filesize($abs);
                if ($sz !== false) {
                    $size += (int) $sz;
                }
            } elseif (is_dir($abs)) {
                $dirs++;
                $stack[] = $abs;
            } else {
                $files++;
                $sz = @filesize($abs);
                if ($sz !== false) {
                    $size += (int) $sz;
                }
            }
            if ($seen >= $maxEntries || microtime(true) > $deadline) {
                $partial = 1;
                break 2;
            }
        }
    }
    return array('files' => $files, 'dirs' => $dirs, 'size' => $size, 'partial' => $partial);
}

/* 当前文件夹统计（相对路径入口），口径与 dir_stats_abs 一致 */
function dir_stats($rel)
{
    $dir = resolve_path($rel);
    if (!is_dir($dir)) {
        api_fail('不是文件夹');
    }
    if (!is_readable($dir)) {
        api_fail(t('perm_denied'), 403);
    }
    $st = dir_stats_abs($dir);
    return array(
        'path'     => (string) $rel,
        'files'    => $st['files'],
        'dirs'     => $st['dirs'],
        'size'     => $st['size'],
        'sizeText' => human_size($st['size']),
        'partial'  => $st['partial'],
    );
}

function walk_files($base,  $query,  $limit,  $dirsToo) 
{
    $out = array();
    $query = strtolower($query);
    $stack = array($base);
    while ($stack && count($out) < $limit) {
        $dir = array_pop($stack);
        $names = @scandir($dir);
        if ($names === false) {
            continue;
        }
        foreach ($names as $name) {
            if ($name === '.' || $name === '..' || !visible_name($name)) {
                continue;
            }
            $abs = $dir . '/' . $name;
            $isDir = is_dir($abs);
            if ($isDir) {
                $stack[] = $abs;
                if ($dirsToo && ($query === '' || strpos(strtolower($name), $query) !== false)) {
                    $out[] = item_of($abs);
                }
                continue;
            }
            if ($query !== '' && strpos(strtolower($name), $query) === false) {
                continue;
            }
            $out[] = item_of($abs);
            if (count($out) >= $limit) {
                break;
            }
        }
    }
    return $out;
}

function storage_info() 
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $root = root_dir();
    $probes = array($root, dirname($root), '.');
    $total = false;
    $free = false;
    if (xz_fn_ok('disk_total_space')) {
        foreach ($probes as $probe) {
            $val = @disk_total_space($probe);
            if ($val !== false && $val > 0) {
                $total = (float) $val;
                break;
            }
        }
    }
    if (xz_fn_ok('disk_free_space')) {
        foreach ($probes as $probe) {
            $val = @disk_free_space($probe);
            if ($val !== false && $val > 0) {
                $free = (float) $val;
                break;
            }
        }
    }
    /* 读取不到容量时 known = 0，前端会隐藏整块存储卡片，而不是显示「—」 */
    $known = ($total !== false && $total > 0 && $free !== false);
    if (!$known) {
        $cache = array(
            'known' => 0,
            'total' => 0,
            'free'  => 0,
            'used'  => 0,
            'percent' => 0,
            'totalText' => '',
            'freeText'  => '',
            'usedText'  => '',
        );
        return $cache;
    }
    if ($free > $total) {
        $free = $total;
    }
    $used = max(0, $total - $free);
    $cache = array(
        'known' => 1,
        'total' => (int) $total,
        'free'  => (int) $free,
        'used'  => (int) $used,
        'percent' => $total > 0 ? round($used / $total * 100, 1) : 0,
        'totalText' => human_size($total),
        'freeText'  => human_size($free),
        'usedText'  => human_size($used),
    );
    return $cache;
}

/* ------------------------------ 直链签名 ------------------------------ */

function b64url_encode($data) 
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64url_decode($data) 
{
    $pad = strlen($data) % 4;
    if ($pad) {
        $data .= str_repeat('=', 4 - $pad);
    }
    $out = base64_decode(strtr($data, '-_', '+/'), true);
    return $out === false ? '' : $out;
}

function sign_link($rel,  $ttl = 604800) 
{
    $payload = b64url_encode(json_encode(array('p' => $rel, 'e' => time() + $ttl)));
    $sig = b64url_encode(hash_hmac('sha256', $payload, secret(), true));
    return $payload . '.' . $sig;
}

function parse_link($token) 
{
    $parts = explode('.', $token);
    if (count($parts) !== 2) {
        api_fail('链接格式不正确', 400);
    }
    $expected = b64url_encode(hash_hmac('sha256', $parts[0], secret(), true));
    if (!hash_equals($expected, $parts[1])) {
        api_fail('链接无效', 403);
    }
    $data = json_decode(b64url_decode($parts[0]), true);
    if (!is_array($data) || !isset($data['p'], $data['e'])) {
        api_fail('链接无效', 403);
    }
    if ((int) $data['e'] < time()) {
        api_fail('链接已过期', 410);
    }
    return (string) $data['p'];
}

function base_url() 
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    $scheme = $https ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : 'localhost';
    $path = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '/';
    return $scheme . '://' . $host . $path;
}

/* ------------------------------ 直链 ------------------------------ */

function link_style()
{
    $style = strtolower(trim((string) setting('link_style', 'pretty')));
    return $style === 'param' ? 'param' : 'pretty';
}

/**
 * 生成文件直链。
 * pretty（默认）：{站点}/{安装目录}{文件相对路径}，不带脚本名、不带任何参数，
 *                 由 Web 服务器直接把文件返回给浏览器（与文件夹直链风格一致）
 * param         ：{站点}/{本文件.php}?dl=签名，兼容不支持静态直连或路径扩展（PATH_INFO）的服务器
 */
function direct_url($rel)
{
    $rel = trim(str_replace('\\', '/', (string) $rel), '/');
    if (link_style() === 'param') {
        return base_url() . '?dl=' . sign_link($rel);
    }
    return site_path_url($rel);
}

/**
 * 站点根地址 + 文件相对路径，得到 https://站点/文件路径 这种纯路径直链。
 * 程序根目录若位于站点目录之内，会自动带上中间的相对目录；
 * 若根目录在站点目录之外（无法静态访问），退回「脚本名 + 路径」形式，保证链接仍然可用。
 */
function site_path_url($rel)
{
    $rel = trim(str_replace('\\', '/', (string) $rel), '/');
    $prefix = root_web_prefix();
    if ($prefix === null) {
        return $rel === '' ? base_url() : base_url() . '/' . encode_rel($rel);
    }
    $base = site_root_url();
    if ($prefix !== '') {
        $base .= '/' . encode_rel($prefix);
    }
    $tail = encode_rel($rel);
    return $tail === '' ? $base . '/' : $base . '/' . $tail;
}

/**
 * 程序根目录相对「站点安装目录」的路径（''=同一目录，null=不在站点目录内）。
 */
function root_web_prefix()
{
    static $done = false;
    static $prefix = null;
    if ($done) {
        return $prefix;
    }
    $done = true;
    $scriptDir = @realpath(dirname(__FILE__));
    if ($scriptDir === false) {
        return null;
    }
    $scriptDir = rtrim(str_replace('\\', '/', $scriptDir), '/');
    $root = rtrim(str_replace('\\', '/', root_dir()), '/');
    if ($root === $scriptDir) {
        $prefix = '';
    } elseif ($scriptDir !== '' && strpos($root . '/', $scriptDir . '/') === 0) {
        $prefix = trim(substr($root, strlen($scriptDir)), '/');
    } else {
        $prefix = null;
    }
    return $prefix;
}

/**
 * 按路径分段做 URL 编码，保留 / 分隔，避免中文、空格被截断。
 */
function encode_rel($rel)
{
    $rel = trim(str_replace('\\', '/', (string) $rel), '/');
    if ($rel === '') {
        return '';
    }
    $segs = array();
    foreach (explode('/', $rel) as $seg) {
        if ($seg === '') {
            continue;
        }
        $segs[] = rawurlencode($seg);
    }
    return implode('/', $segs);
}

/**
 * 站点根地址（scheme://host/安装目录），不含脚本文件名。
 * 文件夹直链用它拼接，得到 https://站点/文件夹/ 这种不带 .php 的形式。
 */
function site_root_url()
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    $scheme = $https ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : 'localhost';
    $script = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', (string) $_SERVER['SCRIPT_NAME']) : '/';
    $dir = str_replace('\\', '/', dirname($script));
    $dir = ($dir === '.' || $dir === '//') ? '' : rtrim($dir, '/');
    return $scheme . '://' . $host . $dir;
}

/**
 * 生成文件夹直链。
 * pretty（默认）：{站点}/{文件夹相对路径}/，不带脚本名、不带任何参数
 * param         ：{站点}/{本文件.php}?p=相对路径，兼容不支持站点根路径解析的服务器
 */
function dir_url($rel)
{
    $rel = trim(str_replace('\\', '/', (string) $rel), '/');
    if (link_style() === 'param') {
        return base_url() . '?p=' . rawurlencode($rel);
    }
    $tail = encode_rel($rel);
    return site_root_url() . '/' . ($tail === '' ? '' : $tail . '/');
}

/**
 * 解析「站点根目录 + 文件夹路径」形式的文件夹直链（如 /123/）。
 * 仅当目标确实是已存在的目录时返回相对路径，避免影响其它正常请求。
 */
function pretty_dir_path()
{
    if (isset($_SERVER['PATH_INFO']) && (string) $_SERVER['PATH_INFO'] !== '') {
        return '';
    }
    if (!isset($_SERVER['REQUEST_URI'])) {
        return '';
    }
    $uri = (string) $_SERVER['REQUEST_URI'];
    $q = strpos($uri, '?');
    if ($q !== false) {
        $uri = substr($uri, 0, $q);
    }
    $script = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';
    if ($script !== '' && strpos($uri, $script) === 0) {
        return '';
    }
    // 程序装在子目录时，去掉安装目录前缀（如 /fm/123/ -> 123）
    $baseDir = rtrim(str_replace('\\', '/', dirname($script)), '/');
    if ($baseDir !== '' && $baseDir !== '.' && strpos($uri, $baseDir . '/') === 0) {
        $uri = substr($uri, strlen($baseDir));
    }
    $raw = trim(str_replace('\\', '/', $uri), '/');
    if ($raw === '') {
        return '';
    }
    $segs = array();
    foreach (explode('/', $raw) as $seg) {
        $seg = rawurldecode($seg);
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..' || strpos($seg, "\0") !== false) {
            return '';
        }
        $segs[] = $seg;
    }
    $rel = implode('/', $segs);
    if ($rel === '') {
        return '';
    }
    $abs = resolve_path($rel);
    if (!is_dir($abs)) {
        return '';
    }
    $real = rel_path($abs);
    return $real === '' ? '' : $real;
}

/**
 * 从 PATH_INFO / REQUEST_URI 中解析简洁直链携带的文件相对路径。
 * 返回 '' 表示本次请求不是简洁直链请求。
 */
function pretty_path()
{
    $raw = '';
    $encoded = false;
    if (isset($_SERVER['PATH_INFO']) && (string) $_SERVER['PATH_INFO'] !== '') {
        // 多数服务器已对 PATH_INFO 解码
        $raw = (string) $_SERVER['PATH_INFO'];
    } elseif (isset($_SERVER['REQUEST_URI'])) {
        $uri = (string) $_SERVER['REQUEST_URI'];
        $q = strpos($uri, '?');
        if ($q !== false) {
            $uri = substr($uri, 0, $q);
        }
        $script = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';
        if ($script !== '' && strpos($uri, $script . '/') === 0) {
            $raw = substr($uri, strlen($script));
            $encoded = true; // REQUEST_URI 仍是编码状态
        }
    }
    $raw = trim(str_replace('\\', '/', $raw), '/');
    if ($raw === '') {
        return '';
    }
    $segs = array();
    foreach (explode('/', $raw) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($encoded) {
            $seg = rawurldecode($seg);
        }
        if ($seg === '..' || strpos($seg, "\0") !== false) {
            return '';
        }
        $segs[] = $seg;
    }
    return implode('/', $segs);
}

function link_error_page($e)
{
    $code = (int) $e->getCode();
    http_response_code($code >= 400 ? $code : 400);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>链接不可用</title>'
        . '<div style="font:15px/1.7 -apple-system,PingFang SC,sans-serif;padding:40px;text-align:center">'
        . '<h2 style="font-size:18px">' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</h2>'
        . '<p style="color:#888">请回到文件管理器重新复制直链</p></div>';
    exit;
}

/* ------------------------------ 文件输出 ------------------------------ */

function serve_file($rel,  $inline) 
{
    $abs = resolve_path($rel);
    if (is_dir($abs)) {
        api_fail('这是一个文件夹，请使用文件夹链接');
    }
    if (!is_file($abs) || !is_readable($abs)) {
        api_fail(t('not_found'), 404);
    }
    $name = basename($abs);
    $ext = ext_of($name);
    $mime = mime_of($ext);
    if ($ext === 'html' || $ext === 'htm' || $ext === 'svg') {
        // 避免用户上传的页面在同源下执行脚本
        header('Content-Security-Policy: sandbox; default-src \'none\'; img-src data:; style-src \'unsafe-inline\'');
    }
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    /* 支持 Range 请求：视频 / 音频拖动进度、iOS 原生播放器与 HLS 分片都依赖它 */
    $size = (int) @filesize($abs);
    $start = 0;
    $end = $size > 0 ? $size - 1 : 0;
    $partial = false;
    $range = isset($_SERVER['HTTP_RANGE']) ? trim((string) $_SERVER['HTTP_RANGE']) : '';
    if ($range !== '' && $size > 0 && preg_match('/^bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/i', $range, $rm)) {
        $hasStart = $rm[1] !== '';
        $hasEnd = $rm[2] !== '';
        if ($hasStart) {
            $start = (int) $rm[1];
            if ($hasEnd) {
                $end = (int) $rm[2];
            }
        } elseif ($hasEnd) {
            $suffix = (int) $rm[2];
            if ($suffix > 0) {
                $start = max(0, $size - $suffix);
            }
        }
        if ($start > $end || $start >= $size) {
            header('Content-Range: bytes */' . $size);
            http_response_code(416);
            header('Content-Length: 0');
            exit;
        }
        if ($end >= $size) {
            $end = $size - 1;
        }
        $partial = true;
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . ($partial ? ($end - $start + 1) : $size));
    header('Accept-Ranges: bytes');
    header('X-Content-Type-Options: nosniff');
    if ($partial) {
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        http_response_code(206);
    }
    $ascii = preg_replace('/[^\x20-\x7e]/', '_', $name);
    $disposition = $inline ? 'inline' : 'attachment';
    header('Content-Disposition: ' . $disposition . '; filename="' . addcslashes($ascii, '"\\') . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Cache-Control: private, max-age=0, must-revalidate');
    if (!$inline) {
        header('Pragma: public');
    }
    $fp = @fopen($abs, 'rb');
    if ($fp === false) {
        api_fail('无法读取文件', 500);
    }
    if ($start > 0) {
        @fseek($fp, $start);
    }
    $left = $partial ? ($end - $start + 1) : $size;
    while ($left > 0 && !feof($fp)) {
        $chunk = fread($fp, $left > 262144 ? 262144 : $left);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $left -= strlen($chunk);
        echo $chunk;
        @flush();
    }
    fclose($fp);
    exit;
}

/* ------------------------------ HLS（m3u8）播放列表代理 ------------------------------ */

/* 把播放列表里的相对地址解析成相对根目录的路径 */
function hls_norm_rel($baseDir,  $uri) 
{
    $parts = array();
    if (strpos($uri, '/') !== 0 && $baseDir !== '') {
        $parts = explode('/', $baseDir);
    }
    $uri = ltrim($uri, '/');
    foreach (explode('/', $uri) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $seg;
    }
    return implode('/', $parts);
}

/* 把播放列表中的一个 URI 改写为本站代理地址；外链与 data URI 原样保留 */
function hls_rewrite_uri($uri,  $baseDir) 
{
    $uri = trim($uri);
    if ($uri === '') {
        return $uri;
    }
    if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $uri) && !preg_match('#^file:#i', $uri)) {
        return $uri;
    }
    $suffix = '';
    $hash = strpos($uri, '#');
    if ($hash !== false) {
        $suffix = substr($uri, $hash);
        $uri = substr($uri, 0, $hash);
    }
    $q = strpos($uri, '?');
    if ($q !== false) {
        $uri = substr($uri, 0, $q);
    }
    if ($uri === '') {
        return $uri;
    }
    $rel = hls_norm_rel($baseDir, rawurldecode($uri));
    if ($rel === '') {
        return $uri;
    }
    $ext = strtolower((string) pathinfo($rel, PATHINFO_EXTENSION));
    $api = ($ext === 'm3u8' || $ext === 'm3u') ? 'hls' : 'raw';
    return '?api=' . $api . '&path=' . rawurlencode($rel) . $suffix;
}

/* 输出改写后的 m3u8：分片与子播放列表都走本文件，自动带上登录态 */
function serve_hls($rel) 
{
    $abs = resolve_path($rel);
    if (is_dir($abs) || !is_file($abs)) {
        api_fail(t('not_found'), 404);
    }
    $ext = ext_of($abs);
    if ($ext !== 'm3u8' && $ext !== 'm3u') {
        api_fail('该文件不是 m3u8 播放列表');
    }
    if ((int) @filesize($abs) > 8388608) {
        api_fail('播放列表过大，无法在线预览');
    }
    if (!is_readable($abs)) {
        api_fail('无法读取文件', 403);
    }
    $text = (string) @file_get_contents($abs);
    if (strncmp($text, "\xEF\xBB\xBF", 3) === 0) {
        $text = substr($text, 3);
    }
    $dir = rel_path(dirname($abs));
    $lines = preg_split('/\r\n|\r|\n/', $text);
    $out = array();
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '') {
            $out[] = '';
            continue;
        }
        if ($trim[0] === '#') {
            /* 标签里的 URI="..." 属性：密钥、初始化分片、子列表、字幕等 */
            if (preg_match_all('/URI="([^"]*)"/i', $line, $mm)) {
                $n = count($mm[1]);
                for ($i = 0; $i < $n; $i++) {
                    $old = $mm[1][$i];
                    $new = hls_rewrite_uri($old, $dir);
                    if ($new !== $old && $old !== '') {
                        $line = str_replace('URI="' . $old . '"', 'URI="' . $new . '"', $line);
                    }
                }
            }
            $out[] = $line;
            continue;
        }
        $out[] = hls_rewrite_uri($trim, $dir);
    }
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/vnd.apple.mpegurl; charset=utf-8');
    header('Accept-Ranges: none');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo implode("\n", $out);
    exit;
}

/* ------------------------------ 归档：写入 ------------------------------ */

function dos_time($ts) 
{
    $d = getdate($ts > 315532800 ? $ts : time());
    $time = (($d['hours'] & 0x1F) << 11) | (($d['minutes'] & 0x3F) << 5) | (($d['seconds'] >> 1) & 0x1F);
    $year = max(1980, (int) $d['year']);
    $date = (($year - 1980) << 9) | (($d['mon'] & 0x0F) << 5) | ($d['mday'] & 0x1F);
    return array($time, $date);
}

function archive_walk($abs, $local, &$entries)
{
    if (is_dir($abs) && !is_link($abs)) {
        $entries[] = array('abs' => $abs, 'name' => $local, 'dir' => true, 'size' => 0, 'mtime' => (int) @filemtime($abs));
        $names = @scandir($abs);
        if ($names === false) {
            return;
        }
        sort($names);
        foreach ($names as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            archive_walk($abs . '/' . $name, $local . '/' . $name, $entries);
        }
        return;
    }
    if (is_file($abs)) {
        $entries[] = array('abs' => $abs, 'name' => $local, 'dir' => false, 'size' => (int) @filesize($abs), 'mtime' => (int) @filemtime($abs));
    }
}

function archive_entries($paths) 
{
    $entries = array();
    foreach ($paths as $path) {
        $abs = resolve_path($path);
        if (rel_path($abs) === '') {
            continue;
        }
        archive_walk($abs, basename($abs), $entries);
    }
    return $entries;
}

function zip_write($target,  $entries,  $level = 6) 
{
    $fp = @fopen($target, 'wb');
    if ($fp === false) {
        return false;
    }
    $offset = 0;
    $central = '';
    $count = 0;
    foreach ($entries as $entry) {
        $name = ltrim(str_replace('\\', '/', (string) $entry['name']), '/');
        if ($name === '') {
            continue;
        }
        list($dtime, $ddate) = dos_time((int) $entry['mtime']);
        if (!empty($entry['dir'])) {
            $name .= '/';
            $local = pack('VvvvvvVVVvv', 0x04034b50, 20, 0x0800, 0, $dtime, $ddate, 0, 0, 0, strlen($name), 0) . $name;
            fwrite($fp, $local);
            $central .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 0x031E, 20, 0x0800, 0, $dtime, $ddate, 0, 0, 0, strlen($name), 0, 0, 0, 0, 0x41ED0010, $offset) . $name;
            $offset += strlen($local);
            $count++;
            continue;
        }
        $abs = (string) $entry['abs'];
        $src = @fopen($abs, 'rb');
        if ($src === false) {
            continue;
        }
        $usize = (int) @filesize($abs);
        $crc = (int) hexdec((string) @hash_file('crc32b', $abs));
        $method = 0;
        $csize = $usize;
        $tmp = fopen('php://temp/maxmemory:4194304', 'w+b');
        if ($level > 0 && $usize > 0 && $usize <= 67108864) {
            $raw = (string) @file_get_contents($abs);
            $packed = @gzdeflate($raw, $level);
            if (is_string($packed) && strlen($packed) > 0 && strlen($packed) < $usize) {
                fwrite($tmp, $packed);
                $csize = strlen($packed);
                $method = 8;
            }
        }
        if ($csize >= $usize) {
            $method = 0;
            $csize = $usize;
        }
        $header = pack('VvvvvvVVVvv', 0x04034b50, 20, 0x0800, $method, $dtime, $ddate, $crc, $csize, $usize, strlen($name), 0) . $name;
        fwrite($fp, $header);
        if ($method === 8) {
            rewind($tmp);
            stream_copy_to_stream($tmp, $fp);
        } else {
            rewind($src);
            stream_copy_to_stream($src, $fp);
        }
        fclose($tmp);
        fclose($src);
        $central .= pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 0x031E, 20, 0x0800, $method, $dtime, $ddate, $crc, $csize, $usize, strlen($name), 0, 0, 0, 0, 0x81A40000, $offset) . $name;
        $offset += strlen($header) + ($method === 8 ? $csize : $usize);
        $count++;
    }
    $cdOffset = $offset;
    fwrite($fp, $central);
    fwrite($fp, pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen($central), $cdOffset, 0));
    fclose($fp);
    return true;
}

function tar_header($name,  $size,  $mtime,  $mode,  $type) 
{
    $name = str_replace('\\', '/', $name);
    $prefix = '';
    if (strlen($name) > 100) {
        $cut = strrpos(substr($name, 0, 156), '/');
        if ($cut !== false) {
            $prefix = substr($name, 0, $cut);
            $name = substr($name, $cut + 1);
        }
        $name = substr($name, 0, 100);
        $prefix = substr($prefix, 0, 155);
    }
    $header = str_pad($name, 100, "\0")
        . sprintf('%07o', $mode & 07777) . "\0"
        . sprintf('%07o', 0) . "\0"
        . sprintf('%07o', 0) . "\0"
        . sprintf('%011o', $size) . "\0"
        . sprintf('%011o', $mtime) . "\0"
        . '        '
        . $type . str_repeat("\0", 99)
        . 'ustar' . "\0" . '00'
        . str_pad('www-data', 32, "\0")
        . str_pad('www-data', 32, "\0")
        . sprintf('%07o', 0) . "\0"
        . sprintf('%07o', 0) . "\0"
        . str_pad($prefix, 155, "\0")
        . str_repeat("\0", 12);
    $sum = 0;
    for ($i = 0; $i < 512; $i++) {
        $sum += ord($header[$i]);
    }
    $checksum = sprintf('%06o', $sum) . "\0 ";
    $header = substr_replace($header, $checksum, 148, 8);
    return $header;
}

function tar_write_gz($target,  $entries,  $level = 6) 
{
    $tmp = @tmpfile();
    if ($tmp === false) {
        return false;
    }
    foreach ($entries as $entry) {
        $name = ltrim(str_replace('\\', '/', (string) $entry['name']), '/');
        if ($name === '') {
            continue;
        }
        $mtime = (int) $entry['mtime'];
        if (!empty($entry['dir'])) {
            fwrite($tmp, tar_header($name . '/', 0, $mtime, 0755, '5'));
            continue;
        }
        $size = (int) @filesize((string) $entry['abs']);
        $src = @fopen((string) $entry['abs'], 'rb');
        if ($src === false) {
            continue;
        }
        fwrite($tmp, tar_header($name, $size, $mtime, 0644, '0'));
        $written = 0;
        while (!feof($src)) {
            $buf = fread($src, 262144);
            if ($buf === false || $buf === '') {
                break;
            }
            fwrite($tmp, $buf);
            $written += strlen($buf);
        }
        fclose($src);
        $pad = (512 - ($written % 512)) % 512;
        if ($pad > 0) {
            fwrite($tmp, str_repeat("\0", $pad));
        }
    }
    fwrite($tmp, str_repeat("\0", 1024));
    rewind($tmp);
    $out = @gzopen($target, 'wb' . (int) $level);
    if ($out === false) {
        fclose($tmp);
        return false;
    }
    while (!feof($tmp)) {
        $buf = fread($tmp, 262144);
        if ($buf === false || $buf === '') {
            break;
        }
        gzwrite($out, $buf);
    }
    gzclose($out);
    fclose($tmp);
    return true;
}

function compress_to($dir,  $format,  $paths,  $baseName,  $level = 6) 
{
    $entries = archive_entries($paths);
    if (count($entries) === 0) {
        api_fail('没有可压缩的内容');
    }
    $safe = check_name($baseName);
    $ext = $format === 'tar.gz' ? '.tar.gz' : '.zip';
    if (substr(strtolower($safe), -strlen($ext)) === $ext) {
        $safe = substr($safe, 0, -strlen($ext));
    }
    $target = unique_path($dir, $safe . $ext);
    if ($format === 'tar.gz') {
        if (!function_exists('gzopen') || !function_exists('gzdeflate')) {
            api_fail('服务器缺少 zlib 扩展，无法生成 tar.gz');
        }
        $ok = tar_write_gz($target, $entries, $level);
    } else {
        $ok = zip_write($target, $entries, $level);
    }
    if (!$ok) {
        @unlink($target);
        api_fail('压缩失败，请检查目录写入权限');
    }
    @chmod($target, 0644);
    return $target;
}

/* ------------------------------ 归档：读取 ------------------------------ */

function safe_entry_name($name) 
{
    $name = str_replace('\\', '/', $name);
    $name = ltrim($name, '/');
    if ($name === '' || strpos($name, "\0") !== false) {
        return '';
    }
    $parts = explode('/', $name);
    foreach ($parts as $part) {
        if ($part === '..') {
            return '';
        }
    }
    return $name;
}

/* ------------------------------ 归档：ZIP 内容预览 ------------------------------ */

/* 读取 ZIP64 的 64 位小端整数（PHP 5.2 无 64 位解包格式） */
function zip_u64($bin,  $offset) 
{
    if (strlen($bin) < $offset + 8) {
        return 0;
    }
    $parts = unpack('Vlow/Vhigh', substr($bin, $offset, 8));
    $value = (float) $parts['high'] * 4294967296.0 + (float) $parts['low'];
    if ($value <= 2147483647.0) {
        return (int) $value;
    }
    return $value;
}

/* DOS 日期时间转 Unix 时间戳 */
function zip_dos_ts($date,  $time) 
{
    $year = (($date >> 9) & 0x7F) + 1980;
    $month = ($date >> 5) & 0x0F;
    $day = $date & 0x1F;
    $hour = ($time >> 11) & 0x1F;
    $minute = ($time >> 5) & 0x3F;
    $second = ($time & 0x1F) * 2;
    if ($month < 1 || $month > 12) {
        $month = 1;
    }
    if ($day < 1 || $day > 31) {
        $day = 1;
    }
    $ts = @mktime($hour, $minute, $second, $month, $day, $year);
    return $ts === false ? 0 : (int) $ts;
}

/* ZIP 内文件名：未标记 UTF-8 时按 GBK 还原中文名 */
function zip_name_from_raw($raw,  $flags) 
{
    $name = str_replace('\\', '/', (string) $raw);
    if (((int) $flags & 0x0800) === 0 && preg_match('/[\x80-\xff]/', $name)) {
        if (function_exists('iconv')) {
            $conv = @iconv('GBK', 'UTF-8//IGNORE', $name);
            if (is_string($conv) && $conv !== '' && preg_match('//u', $conv)) {
                $name = $conv;
            }
        }
    }
    return $name;
}

/* 解析中央目录，返回条目列表与统计信息（最多 $limit 条） */
function zip_index($zipPath,  $limit = 5000) 
{
    $empty = array('entries' => array(), 'total' => 0, 'files' => 0, 'folders' => 0,
        'bytes' => 0, 'compressed' => 0, 'truncated' => false);
    $fp = @fopen($zipPath, 'rb');
    if ($fp === false) {
        api_fail('无法读取压缩包');
    }
    $size = (int) @filesize($zipPath);
    if ($size < 22) {
        fclose($fp);
        api_fail('不是有效的 ZIP 文件');
    }
    $tailLen = min($size, 66000);
    fseek($fp, $size - $tailLen);
    $tail = (string) fread($fp, $tailLen);
    $pos = strrpos($tail, "PK\x05\x06");
    if ($pos === false) {
        fclose($fp);
        api_fail('不是有效的 ZIP 文件');
    }
    $eocdOffset = $size - $tailLen + $pos;
    fseek($fp, $eocdOffset);
    $eocd = (string) fread($fp, 22);
    if (strlen($eocd) < 22) {
        fclose($fp);
        api_fail('压缩包结构损坏');
    }
    $info = unpack('Vsig/vdisk/vcddisk/vcount/vtotal/Vcdsize/Vcdoffset/vcomment', $eocd);
    $count = (int) $info['total'];
    $cdOffset = (float) $info['cdoffset'];
    $cdSize = (float) $info['cdsize'];

    /* Zip64：条目数或目录尺寸 / 偏移溢出 32 位时，从 Zip64 记录读取真实值 */
    if (($count === 0xFFFF || $cdOffset >= 4294967295.0 || $cdSize >= 4294967295.0) && $eocdOffset >= 20) {
        fseek($fp, $eocdOffset - 20);
        $loc = (string) fread($fp, 20);
        if (substr($loc, 0, 4) === "PK\x06\x07") {
            $zoff = zip_u64($loc, 8);
            if ($zoff > 0 && $zoff < $size) {
                fseek($fp, (int) $zoff);
                $zrec = (string) fread($fp, 56);
                if (substr($zrec, 0, 4) === "PK\x06\x06" && strlen($zrec) >= 56) {
                    $count = (int) zip_u64($zrec, 32);
                    $cdSize = zip_u64($zrec, 40);
                    $cdOffset = zip_u64($zrec, 48);
                }
            }
        }
    }

    if ($count < 0 || $cdOffset < 0 || $cdSize < 0) {
        fclose($fp);
        api_fail('压缩包结构损坏');
    }
    if ($count === 0) {
        fclose($fp);
        return $empty;
    }
    if ($cdOffset + $cdSize > $size) {
        fclose($fp);
        api_fail('压缩包结构损坏');
    }

    /* 只读取需要的目录区，避免超大压缩包一次性占满内存 */
    $readLen = (int) min($cdSize, 16777216);
    fseek($fp, (int) $cdOffset);
    $cd = (string) fread($fp, $readLen);
    $cdLen = strlen($cd);
    $p = 0;
    $entries = array();
    $files = 0;
    $folders = 0;
    $bytes = 0;
    $compressed = 0;
    for ($i = 0; $i < $count; $i++) {
        if ($p + 46 > $cdLen) {
            break;
        }
        $head = unpack('Vsig/vmade/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen/vcommentlen/vdisk/vinternal/Vexternal/Voffset', substr($cd, $p, 46));
        if ((int) $head['sig'] !== 0x02014b50) {
            break;
        }
        $nameLen = (int) $head['namelen'];
        $extraLen = (int) $head['extralen'];
        $commentLen = (int) $head['commentlen'];
        if ($p + 46 + $nameLen + $extraLen + $commentLen > $cdLen) {
            break;
        }
        $rawName = substr($cd, $p + 46, $nameLen);
        $extra = substr($cd, $p + 46 + $nameLen, $extraLen);
        $p += 46 + $nameLen + $extraLen + $commentLen;

        $usize = (float) $head['usize'];
        $csize = (float) $head['csize'];
        $offset = (float) $head['offset'];
        if ($usize >= 4294967295.0 || $csize >= 4294967295.0 || $offset >= 4294967295.0) {
            /* Zip64 扩展字段按 usize / csize / offset 的顺序存放 */
            $ep = 0;
            $elen = strlen($extra);
            while ($ep + 4 <= $elen) {
                $eh = unpack('vid/vlen', substr($extra, $ep, 4));
                $edata = substr($extra, $ep + 4, (int) $eh['len']);
                if ((int) $eh['id'] === 0x0001) {
                    $zp = 0;
                    if ($usize >= 4294967295.0 && strlen($edata) >= $zp + 8) {
                        $usize = zip_u64($edata, $zp);
                        $zp += 8;
                    }
                    if ($csize >= 4294967295.0 && strlen($edata) >= $zp + 8) {
                        $csize = zip_u64($edata, $zp);
                        $zp += 8;
                    }
                    if ($offset >= 4294967295.0 && strlen($edata) >= $zp + 8) {
                        $offset = zip_u64($edata, $zp);
                        $zp += 8;
                    }
                    break;
                }
                $ep += 4 + (int) $eh['len'];
            }
        }

        $name = safe_entry_name(zip_name_from_raw($rawName, (int) $head['flags']));
        if ($name === '') {
            continue;
        }
        $isDir = substr($name, -1) === '/' || (((int) $head['external'] >> 16) & 0xF000) === 0x4000;
        if ($isDir && substr($name, -1) !== '/') {
            $name .= '/';
        }
        if (count($entries) < $limit) {
            $entries[] = array(
                'i'        => count($entries),
                'name'     => $name,
                'dir'      => $isDir ? true : false,
                'size'     => (int) $usize,
                'csize'    => (int) $csize,
                'mtime'    => zip_dos_ts((int) $head['date'], (int) $head['time']),
                'method'   => (int) $head['method'],
                'locked'   => ((int) $head['flags'] & 0x0001) ? true : false,
                'crc'      => (float) $head['crc'],
                'offset'   => (int) $offset,
            );
        }
        if ($isDir) {
            $folders++;
        } else {
            $files++;
            $bytes += $usize;
            $compressed += $csize;
        }
    }
    fclose($fp);
    return array(
        'entries'    => $entries,
        'total'      => $count,
        'files'      => $files,
        'folders'    => $folders,
        'bytes'      => $bytes,
        'compressed' => $compressed,
        'truncated'  => count($entries) < $count,
    );
}

/* 读取单个条目的完整内容；$maxBytes 为解压后上限 */
function xz_zip_entry_read($zipPath,  $index,  $maxBytes = 8388608) 
{
    $index = (int) $index;
    if ($index < 0) {
        api_fail('压缩包内未找到该文件');
    }
    $idx = zip_index($zipPath, $index + 1);
    if (!isset($idx['entries'][$index])) {
        api_fail('压缩包内未找到该文件');
    }
    $entry = $idx['entries'][$index];
    if (!empty($entry['dir'])) {
        api_fail('这是一个文件夹');
    }
    if (!empty($entry['locked'])) {
        api_fail('该文件已加密，无法预览');
    }
    if ((float) $entry['size'] > (float) $maxBytes) {
        api_fail('文件过大，无法在线预览');
    }
    if ((int) $entry['method'] !== 0 && (int) $entry['method'] !== 8) {
        api_fail('该压缩方式暂不支持预览');
    }

    $fp = @fopen($zipPath, 'rb');
    if ($fp === false) {
        api_fail('无法读取压缩包');
    }
    fseek($fp, (int) $entry['offset']);
    $lh = (string) fread($fp, 30);
    if (strlen($lh) < 30 || substr($lh, 0, 4) !== "PK\x03\x04") {
        fclose($fp);
        api_fail('压缩包结构损坏');
    }
    $lhInfo = unpack('Vsig/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen', $lh);
    $dataOffset = (int) $entry['offset'] + 30 + (int) $lhInfo['namelen'] + (int) $lhInfo['extralen'];
    $csize = (int) $entry['csize'];
    if ($csize > 67108864) {
        fclose($fp);
        api_fail('文件过大，无法在线预览');
    }
    fseek($fp, $dataOffset);
    $raw = '';
    $left = $csize;
    while ($left > 0) {
        $buf = fread($fp, (int) min(262144, $left));
        if ($buf === false || $buf === '') {
            break;
        }
        $raw .= $buf;
        $left -= strlen($buf);
    }
    fclose($fp);
    if ($left > 0) {
        api_fail('压缩包内容读取失败');
    }
    if ($csize === 0) {
        $data = '';
    } elseif ((int) $entry['method'] === 8) {
        $data = @gzinflate($raw);
        if ($data === false) {
            api_fail('压缩包内容读取失败');
        }
    } else {
        $data = $raw;
    }
    if (strlen($data) !== (int) $entry['size']) {
        api_fail('压缩包内容校验失败');
    }
    if (function_exists('hash')) {
        $crc = strtolower((string) @hash('crc32b', $data));
        if ($crc !== '' && hexdec($crc) != $entry['crc']) {
            api_fail('压缩包内容校验失败');
        }
    }
    return array('entry' => $entry, 'data' => $data);
}

/* 输出压缩包内单个文件（预览或下载），不落盘 */
function serve_zip_entry($zipPath,  $index,  $download) 
{
    $res = xz_zip_entry_read($zipPath, $index, 33554432);
    $entry = $res['entry'];
    $data = $res['data'];
    $name = basename($entry['name']);
    $ext = ext_of($name);
    $mime = mime_of($ext);
    if ($ext === 'html' || $ext === 'htm' || $ext === 'svg') {
        header('Content-Security-Policy: sandbox; default-src \'none\'; img-src data:; style-src \'unsafe-inline\'');
    }
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . strlen($data));
    header('Accept-Ranges: none');
    header('X-Content-Type-Options: nosniff');
    $ascii = preg_replace('/[^\x20-\x7e]/', '_', $name);
    $disposition = $download ? 'attachment' : 'inline';
    header('Content-Disposition: ' . $disposition . '; filename="' . addcslashes($ascii, '"\\') . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Cache-Control: private, max-age=0, must-revalidate');
    echo $data;
    exit;
}

function zip_extract($zipPath,  $destDir,  $stripPrefix = '',  $dedupe = false) 
{
    $fp = @fopen($zipPath, 'rb');
    if ($fp === false) {
        api_fail('无法读取压缩包');
    }
    $size = (int) @filesize($zipPath);
    $tailLen = min($size, 66000);
    fseek($fp, $size - $tailLen);
    $tail = (string) fread($fp, $tailLen);
    $pos = strrpos($tail, "PK\x05\x06");
    if ($pos === false) {
        fclose($fp);
        api_fail('不是有效的 ZIP 文件');
    }
    fseek($fp, $size - $tailLen + $pos);
    $eocd = (string) fread($fp, 22);
    if (strlen($eocd) < 22) {
        fclose($fp);
        api_fail('压缩包结构损坏');
    }
    $info = unpack('Vsig/vdisk/vcddisk/vcount/vtotal/Vcdsize/Vcdoffset/vcomment', $eocd);
    $count = (int) $info['total'];
    $cdOffset = (int) $info['cdoffset'];
    $cdSize = (int) $info['cdsize'];
    if ($count <= 0 || $count > 50000 || $cdOffset <= 0 || $cdOffset + $cdSize > $size) {
        fclose($fp);
        api_fail('压缩包为空或格式不受支持（Zip64 暂不支持）');
    }
    fseek($fp, $cdOffset);
    $cd = (string) fread($fp, $cdSize);
    $p = 0;
    $totalBytes = 0;
    $written = 0;
    $strip = trim($stripPrefix, '/');
    for ($i = 0; $i < $count; $i++) {
        if ($p + 46 > strlen($cd)) {
            break;
        }
        $head = unpack('Vsig/vmade/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen/vcommentlen/vdisk/vinternal/Vexternal/Voffset', substr($cd, $p, 46));
        if ((int) $head['sig'] !== 0x02014b50) {
            break;
        }
        $name = substr($cd, $p + 46, (int) $head['namelen']);
        $p += 46 + (int) $head['namelen'] + (int) $head['extralen'] + (int) $head['commentlen'];
        $name = safe_entry_name($name);
        if ($name === '') {
            continue;
        }
        if ($strip !== '' && strpos($name, $strip . '/') === 0) {
            $name = substr($name, strlen($strip) + 1);
        }
        if ($name === '') {
            continue;
        }
        $target = $destDir . '/' . $name;
        if (substr($name, -1) === '/') {
            if (!is_dir($target)) {
                @mkdir($target, 0755, true);
            }
            continue;
        }
        @mkdir(dirname($target), 0755, true);
        /* 释放到当前目录时避免覆盖同名文件，自动追加 (2)(3)… */
        if ($dedupe && file_exists($target) && !is_dir($target)) {
            $target = unique_path(dirname($target), basename($target));
        }
        $method = (int) $head['method'];
        $csize = (int) $head['csize'];
        $usize = (int) $head['usize'];
        fseek($fp, (int) $head['offset']);
        $lh = (string) fread($fp, 30);
        if (strlen($lh) < 30) {
            continue;
        }
        $lhInfo = unpack('Vsig/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen', $lh);
        $dataOffset = (int) $head['offset'] + 30 + (int) $lhInfo['namelen'] + (int) $lhInfo['extralen'];
        fseek($fp, $dataOffset);
        $out = @fopen($target, 'wb');
        if ($out === false) {
            continue;
        }
        if ($method === 0) {
            $left = $csize;
            while ($left > 0) {
                $buf = fread($fp, (int) min(262144, $left));
                if ($buf === false || $buf === '') {
                    break;
                }
                fwrite($out, $buf);
                $left -= strlen($buf);
            }
        } else {
            if ($csize > 134217728) {
                fclose($out);
                continue;
            }
            $buf = '';
            $left = $csize;
            while ($left > 0) {
                $part = fread($fp, (int) min(262144, $left));
                if ($part === false || $part === '') {
                    break;
                }
                $left -= strlen($part);
                $buf .= $part;
            }
            $chunk = @gzinflate($buf);
            if (is_string($chunk) && $chunk !== '') {
                fwrite($out, $chunk);
            }
        }
        fclose($out);
        @chmod($target, 0644);
        $written++;
        $totalBytes += $usize > 0 ? $usize : $csize;
    }
    fclose($fp);
    return array('count' => $written, 'bytes' => $totalBytes);
}

function tar_extract_gz($gzPath,  $destDir,  $stripPrefix = '',  $dedupe = false) 
{
    if (!function_exists('gzopen')) {
        api_fail('服务器缺少 zlib 扩展，无法解压 tar.gz');
    }
    $src = @gzopen($gzPath, 'rb');
    if ($src === false) {
        api_fail('无法读取压缩包');
    }
    $tmp = @tmpfile();
    if ($tmp === false) {
        gzclose($src);
        api_fail('临时文件创建失败');
    }
    $outBytes = 0;
    while (!gzeof($src)) {
        $buf = gzread($src, 262144);
        if ($buf === false || $buf === '') {
            break;
        }
        fwrite($tmp, $buf);
        $outBytes += strlen($buf);
        if ($outBytes > 2 * 1024 * 1024 * 1024) {
            gzclose($src);
            fclose($tmp);
            api_fail('压缩包解压后超过 2GB，已中止');
        }
    }
    gzclose($src);
    rewind($tmp);
    $strip = trim($stripPrefix, '/');
    $count = 0;
    $bytes = 0;
    $longName = '';
    while (!feof($tmp)) {
        $block = fread($tmp, 512);
        if ($block === false || strlen($block) < 512) {
            break;
        }
        if (trim($block, "\0") === '') {
            break;
        }
        $name = rtrim(substr($block, 0, 100), "\0");
        $prefix = rtrim(substr($block, 345, 155), "\0");
        if ($prefix !== '') {
            $name = $prefix . '/' . $name;
        }
        $sizeField = trim(substr($block, 124, 12), "\0 ");
        $size = $sizeField === '' ? 0 : (int) octdec($sizeField);
        $type = substr($block, 156, 1);
        $mtime = (int) octdec(trim(substr($block, 136, 12), "\0 "));
        if ($type === 'L') {
            $data = '';
            $left = $size;
            while ($left > 0) {
                $buf = fread($tmp, (int) min(262144, $left));
                if ($buf === false || $buf === '') {
                    break;
                }
                $data .= $buf;
                $left -= strlen($buf);
            }
            $pad = (512 - ($size % 512)) % 512;
            if ($pad > 0) {
                fseek($tmp, $pad, SEEK_CUR);
            }
            $longName = rtrim($data, "\0");
            continue;
        }
        if ($longName !== '') {
            $name = $longName;
            $longName = '';
        }
        $name = safe_entry_name($name);
        if ($name === '') {
            $skip = $size + ((512 - ($size % 512)) % 512);
            fseek($tmp, $skip, SEEK_CUR);
            continue;
        }
        if ($strip !== '' && strpos($name, $strip . '/') === 0) {
            $name = substr($name, strlen($strip) + 1);
        }
        if ($name === '') {
            $skip = $size + ((512 - ($size % 512)) % 512);
            fseek($tmp, $skip, SEEK_CUR);
            continue;
        }
        $target = $destDir . '/' . $name;
        if ($type === '5' || substr($name, -1) === '/') {
            if (!is_dir($target)) {
                @mkdir($target, 0755, true);
            }
            continue;
        }
        if ($type !== '0' && $type !== '' && $type !== '7') {
            $skip = $size + ((512 - ($size % 512)) % 512);
            fseek($tmp, $skip, SEEK_CUR);
            continue;
        }
        @mkdir(dirname($target), 0755, true);
        if ($dedupe && file_exists($target) && !is_dir($target)) {
            $target = unique_path(dirname($target), basename($target));
        }
        $out = @fopen($target, 'wb');
        $left = $size;
        while ($left > 0) {
            $buf = fread($tmp, (int) min(262144, $left));
            if ($buf === false || $buf === '') {
                break;
            }
            if ($out) {
                fwrite($out, $buf);
            }
            $left -= strlen($buf);
        }
        if ($out) {
            fclose($out);
            @chmod($target, 0644);
            @touch($target, $mtime > 0 ? $mtime : time());
        }
        $pad = (512 - ($size % 512)) % 512;
        if ($pad > 0) {
            fseek($tmp, $pad, SEEK_CUR);
        }
        $count++;
        $bytes += $size;
    }
    fclose($tmp);
    return array('count' => $count, 'bytes' => $bytes);
}

/* ------------------------------ 网络请求 ------------------------------ */

function http_request($url,  $options = array()) 
{
    $timeout = isset($options['timeout']) ? (int) $options['timeout'] : 60;
    $headers = isset($options['headers']) ? (array) $options['headers'] : array();
    $saveTo = isset($options['save_to']) ? (string) $options['save_to'] : '';
    $ua = 'EuPHPFileManager/' . XIAZZI_VERSION . ' (+https://github.com)';
    $maxBytes = isset($options['max_bytes']) ? (int) $options['max_bytes'] : 0;
    if ($timeout >= 120) {
        xz_extend_time($timeout + 60);
    }

    /* cURL 优先；免费空间常见 CA 缺失、curl 被关，失败时自动降级到 allow_url_fopen */
    $curlErr = '';
    if (function_exists('curl_init')) {
        foreach (array(true, false) as $verify) {
            $ch = curl_init($url);
            $fp = null;
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 6);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_USERAGENT, $ua);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verify ? 2 : 0);
            if (defined('CURLOPT_ENCODING')) {
                curl_setopt($ch, CURLOPT_ENCODING, '');
            }
            if ($headers) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            }
            if (!empty($options['nobody'])) {
                curl_setopt($ch, CURLOPT_NOBODY, true);
            }
            if ($saveTo !== '') {
                $fp = @fopen($saveTo, 'wb');
                if ($fp === false) {
                    if (PHP_VERSION_ID < 80500) {
                        curl_close($ch);
                    }
                    return array('ok' => false, 'error' => '无法写入目标文件', 'code' => 0, 'body' => '');
                }
                curl_setopt($ch, CURLOPT_FILE, $fp);
            } else {
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            }
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = (string) curl_error($ch);
            $ctype = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            if (PHP_VERSION_ID < 80500) {
                curl_close($ch);
            }
            if ($fp) {
                fclose($fp);
            }
            if ($body !== false) {
                $curlErr = '';
                return array('ok' => $code >= 200 && $code < 300, 'code' => $code, 'body' => is_string($body) ? $body : '', 'type' => $ctype, 'error' => $code >= 300 ? 'HTTP ' . $code : '');
            }
            $curlErr = $err !== '' ? $err : '请求失败';
            @unlink($saveTo);
            /* 仅在证书 / SSL 类错误时再试一次不校验证书，其它错误直接跳出 */
            if ($verify && !preg_match('/(SSL|certificate|CA |verify)/i', $curlErr)) {
                break;
            }
        }
    }

    if (!ini_get('allow_url_fopen')) {
        return array('ok' => false, 'error' => $curlErr !== '' ? ('网络请求失败：' . $curlErr) : '服务器未启用 curl 且禁用了 allow_url_fopen', 'code' => 0, 'body' => '');
    }
    $headerLines = "User-Agent: " . $ua . "\r\n";
    foreach ($headers as $line) {
        $headerLines .= $line . "\r\n";
    }
    $context = stream_context_create(array(
        'http' => array('method' => 'GET', 'header' => $headerLines, 'timeout' => $timeout, 'follow_location' => 1, 'max_redirects' => 6, 'ignore_errors' => true),
        'ssl'  => array('verify_peer' => true, 'verify_peer_name' => true),
    ));
    $src = @fopen($url, 'rb', false, $context);
    if ($src === false) {
        return array('ok' => false, 'error' => '无法连接目标地址', 'code' => 0, 'body' => '');
    }
    $meta = stream_get_meta_data($src);
    $code = 0;
    if (isset($meta['wrapper_data']) && is_array($meta['wrapper_data'])) {
        foreach ($meta['wrapper_data'] as $line) {
            if (preg_match('#^HTTP/\d\.\d\s+(\d{3})#', (string) $line, $m)) {
                $code = (int) $m[1];
            }
        }
    }
    $out = $saveTo !== '' ? @fopen($saveTo, 'wb') : null;
    if ($saveTo !== '' && $out === false) {
        fclose($src);
        return array('ok' => false, 'error' => '无法写入目标文件', 'code' => $code, 'body' => '');
    }
    $body = '';
    $got = 0;
    while (!feof($src)) {
        $buf = fread($src, 262144);
        if ($buf === false || $buf === '') {
            break;
        }
        $got += strlen($buf);
        if ($maxBytes > 0 && $got > $maxBytes) {
            fclose($src);
            if ($out) {
                fclose($out);
            }
            return array('ok' => false, 'error' => '文件超过大小限制', 'code' => $code, 'body' => '');
        }
        if ($out) {
            fwrite($out, $buf);
        } else {
            $body .= $buf;
        }
    }
    fclose($src);
    if ($out) {
        fclose($out);
    }
    return array('ok' => $code >= 200 && $code < 300, 'code' => $code, 'body' => $body, 'type' => '', 'error' => $code >= 300 ? 'HTTP ' . $code : '');
}

function filename_from_url($url,  $fallback = 'download') 
{
    $path = (string) parse_url($url, PHP_URL_PATH);
    $name = basename($path);
    $name = rawurldecode($name);
    $name = preg_replace('/[?#].*$/', '', $name);
    $name = trim((string) $name);
    if ($name === '' || $name === '/' || $name === '.') {
        $name = $fallback;
    }
    if (strpos($name, '.') === false) {
        $name .= '.bin';
    }
    return $name;
}

/* ------------------------------ 文本编码 ------------------------------ */

function encoding_list() 
{
    return array('utf-8', 'gb18030', 'big5', 'utf-16le', 'utf-16be');
}

function normalize_encoding($enc) 
{
    $enc = strtolower(trim($enc));
    if ($enc === '' || $enc === 'auto') {
        return 'auto';
    }
    $map = array(
        'utf8' => 'utf-8', 'utf-8' => 'utf-8',
        'gbk' => 'gb18030', 'gb2312' => 'gb18030', 'gb18030' => 'gb18030',
        'big5' => 'big5', 'big-5' => 'big5',
        'utf-16' => 'utf-16le', 'utf16' => 'utf-16le', 'utf-16le' => 'utf-16le', 'utf-16be' => 'utf-16be',
    );
    return isset($map[$enc]) ? $map[$enc] : 'utf-8';
}

function mb_name($enc) 
{
    $map = array('utf-8' => 'UTF-8', 'gb18030' => 'GB18030', 'big5' => 'BIG-5', 'utf-16le' => 'UTF-16LE', 'utf-16be' => 'UTF-16BE');
    return isset($map[$enc]) ? $map[$enc] : 'UTF-8';
}

/* 严格转码：目标编码无法表示某些字符时返回 false，避免静默丢字 */
function encode_text($text, $to, &$err = null)
{
    $err = '';
    $text = (string) $text;
    if ($text === '') {
        return '';
    }
    if ($to === '' || $to === 'utf-8') {
        return $text;
    }
    $name = mb_name($to);
    if (function_exists('iconv')) {
        $out = @iconv('UTF-8', $name, $text);
        if (is_string($out)) {
            $back = @iconv($name, 'UTF-8', $out);
            if (is_string($back) && $back === $text) {
                return $out;
            }
        }
    }
    if (function_exists('mb_convert_encoding')) {
        $out = @mb_convert_encoding($text, $name, 'UTF-8');
        if (is_string($out) && $out !== '') {
            $back = @mb_convert_encoding($out, 'UTF-8', $name);
            if (is_string($back) && $back === $text) {
                return $out;
            }
        }
    }
    $err = '文件中包含无法用 ' . strtoupper($name) . ' 表示的字符，请改用 UTF-8 保存';
    return false;
}

/* 按目标编码生成写入磁盘的字节；utf-16 自动补 BOM，便于下次自动识别 */
function encode_for_disk($text, $enc, $withBom, &$err)
{
    $err = '';
    $text = (string) $text;
    if (substr($text, 0, 3) === "\xEF\xBB\xBF") {
        $text = substr($text, 3);
    }
    if ($enc === '' || $enc === 'utf-8') {
        return $withBom ? "\xEF\xBB\xBF" . $text : $text;
    }
    $body = encode_text($text, $enc, $err);
    if ($body === false) {
        return false;
    }
    if ($enc === 'utf-16le') {
        return "\xFF\xFE" . $body;
    }
    if ($enc === 'utf-16be') {
        return "\xFE\xFF" . $body;
    }
    return $body;
}

/* 严格解码：用于用户显式指定的编码，失败时返回 false */
function to_utf8_strict($raw, $from)
{
    $name = mb_name($from);
    if (function_exists('iconv')) {
        $out = @iconv($name, 'UTF-8', $raw);
        if (is_string($out) && ($out === '' || preg_match('//u', $out))) {
            return $out;
        }
    }
    if (function_exists('mb_convert_encoding')) {
        $out = @mb_convert_encoding($raw, 'UTF-8', $name);
        if (is_string($out) && ($out === '' || preg_match('//u', $out))) {
            return $out;
        }
    }
    return false;
}

/* 任意编码 -> UTF-8；失败时原样返回 */
function to_utf8($raw,  $from) 
{
    if ($raw === '') {
        return '';
    }
    if (function_exists('mb_convert_encoding')) {
        $out = @mb_convert_encoding($raw, 'UTF-8', mb_name($from));
        if (is_string($out) && ($out !== '' || $raw === '')) {
            return $out;
        }
    }
    if (function_exists('iconv')) {
        $out = @iconv(mb_name($from), 'UTF-8//IGNORE', $raw);
        if (is_string($out)) {
            return $out;
        }
    }
    return $raw;
}

/* UTF-8 -> 目标编码；失败时原样返回 */
function from_utf8($text,  $to) 
{
    if ($text === '' || $to === '' || $to === 'utf-8') {
        return $text;
    }
    if (function_exists('mb_convert_encoding')) {
        $out = @mb_convert_encoding($text, mb_name($to), 'UTF-8');
        if (is_string($out)) {
            return $out;
        }
    }
    if (function_exists('iconv')) {
        $out = @iconv('UTF-8', mb_name($to) . '//IGNORE', $text);
        if (is_string($out)) {
            return $out;
        }
    }
    return $text;
}

/* 自动识别编码并解码成 UTF-8，$detected 回传实际编码 */
function decode_text($raw,  $encoding,  &$detected = null) 
{
    $detected = 'utf-8';
    if (substr($raw, 0, 3) === "\xEF\xBB\xBF") {
        $detected = 'utf-8';
        return substr($raw, 3);
    }
    if (substr($raw, 0, 2) === "\xFF\xFE") {
        $detected = 'utf-16le';
        return to_utf8(substr($raw, 2), 'utf-16le');
    }
    if (substr($raw, 0, 2) === "\xFE\xFF") {
        $detected = 'utf-16be';
        return to_utf8(substr($raw, 2), 'utf-16be');
    }
    $encoding = normalize_encoding($encoding);
    if ($encoding !== 'auto') {
        $detected = $encoding;
        if ($encoding === 'utf-8') {
            return $raw;
        }
        $strict = to_utf8_strict($raw, $encoding);
        return $strict === false ? $raw : $strict;
    }
    if ($raw === '' || preg_match('//u', $raw)) {
        $detected = 'utf-8';
        return $raw;
    }
    foreach (array('gb18030', 'big5') as $try) {
        $conv = to_utf8($raw, $try);
        if ($conv !== '' && preg_match('//u', $conv)) {
            $detected = $try;
            return $conv;
        }
    }
    $detected = 'utf-8';
    return $raw;
}

/* ------------------------------ 鉴权 ------------------------------ */

function auth_enabled() 
{
    global $CONFIG;
    return (bool) $CONFIG['auth'];
}

function remember_cookie_name() 
{
    return 'xiazzi_rm';
}

function issue_remember_cookie($user) 
{
    $exp = time() + 86400 * 30;
    $sig = b64url_encode(hash_hmac('sha256', $user . '|' . $exp, secret(), true));
    $value = b64url_encode($user) . '.' . $exp . '.' . $sig;
    @xz_setcookie(remember_cookie_name(), $value, array(
        'expires'  => $exp,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    ));
}

function clear_remember_cookie() 
{
    @xz_setcookie(remember_cookie_name(), '', array('expires' => time() - 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax'));
}

/* 彻底销毁当前登录态：清空会话数据、删除会话文件与 Cookie、
 * 清除「记住本设备」令牌；$rotate 为真时同时轮换签名密钥，
 * 使其他设备上已签发的记住登录令牌一并失效（改密码/改用户名时使用）。 */
function destroy_auth_session($rotate = false) 
{
    // 1. 清空会话中的全部临时数据（登录用户、CSRF、失败计数等）
    $_SESSION = array();

    // 2. 删除浏览器的会话 Cookie
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        @xz_setcookie(session_name(), '', array(
            'expires'  => time() - 42000,
            'path'     => isset($p['path']) && $p['path'] !== '' ? $p['path'] : '/',
            'domain'   => isset($p['domain']) ? $p['domain'] : '',
            'httponly' => true,
            'samesite' => 'Lax',
            'secure'   => !empty($p['secure']),
        ));
    }

    // 3. 清除自动登录令牌
    clear_remember_cookie();

    // 4. 删除服务器端会话数据
    if (function_exists('session_status')) {
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_destroy();
        }
    } else {
        @session_destroy();
    }

    // 5. 轮换密钥：旧令牌全部作废
    if ($rotate) {
        @settings_write(array('remember_secret' => bin2hex(random_bytes(24))));
    }
}

function check_remember_cookie() 
{
    if (empty($_COOKIE[remember_cookie_name()])) {
        return false;
    }
    $parts = explode('.', (string) $_COOKIE[remember_cookie_name()]);
    if (count($parts) !== 3) {
        return false;
    }
    $user = b64url_decode($parts[0]);
    $exp = (int) $parts[1];
    if ($exp < time() || $user !== effective_user()) {
        return false;
    }
    $expected = b64url_encode(hash_hmac('sha256', $user . '|' . $exp, secret(), true));
    if (!hash_equals($expected, $parts[2])) {
        return false;
    }
    $_SESSION['tfm_user'] = $user;
    return true;
}

function is_logged_in() 
{
    if (!auth_enabled()) {
        return true;
    }
    // 没有设置密码时一律视为未登录，强制先走首次使用引导，
    // 避免旧的会话 / 记住设备令牌绕过设置流程。
    if (setup_required()) {
        return false;
    }
    if (!empty($_SESSION['tfm_user'])) {
        return true;
    }
    return check_remember_cookie();
}

function require_login() 
{
    if (!is_logged_in()) {
        api_fail('登录状态已失效，请重新登录', 401);
    }
}

function require_csrf() 
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }
    $token = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? (string) $_SERVER['HTTP_X_CSRF_TOKEN'] : (string) param('csrf', '');
    $sessionToken = isset($_SESSION['csrf']) ? (string) $_SESSION['csrf'] : '';
    if ($sessionToken === '' || !hash_equals($sessionToken, $token)) {
        api_fail('页面已过期，请刷新后重试', 419);
    }
}

/* ------------------------------ 环境检测 ------------------------------ */

function ini_bytes($key) 
{
    $value = trim((string) ini_get($key));
    if ($value === '') {
        return 0;
    }
    $last = strtolower(substr($value, -1));
    $num = (float) $value;
    switch ($last) {
        case 'g':
            $num *= 1024;
            // no break
        case 'm':
            $num *= 1024;
            // no break
        case 'k':
            $num *= 1024;
    }
    return (int) $num;
}

/* 环境检测行收集器（PHP 5.2 无闭包）：无参调用返回并清空已收集的行 */
function env_row($label = null, $value = '', $state = '', $hint = '')
{
    static $rows = array();
    if (func_num_args() === 0) {
        $out = $rows;
        $rows = array();
        return $out;
    }
    $rows[] = array('label' => $label, 'value' => $value, 'state' => $state, 'hint' => $hint);
    return null;
}

function env_report() 
{
    $rows = array();
    env_row();
    $add = 'env_row';

    $phpOk = version_compare(PHP_VERSION, '5.2.0', '>=');
    $add('PHP', PHP_VERSION, $phpOk ? 'good' : 'bad', $phpOk ? '' : '需要 PHP 5.2 或更高版本');

    $zlib = function_exists('gzopen') && function_exists('gzdeflate') && function_exists('gzinflate');
    $add('zlib', $zlib ? 'enabled' : 'missing', $zlib ? 'good' : 'bad', $zlib ? '' : 'tar.gz 压缩解压与 zip 需要 zlib');

    $add('zip (built-in)', 'bundled', 'good', '内置实现，不依赖 ZipArchive');

    $curl = function_exists('curl_init');
    $urlOpen = (bool) ini_get('allow_url_fopen');
    $add('curl', $curl ? 'enabled' : 'missing', $curl ? 'good' : ($urlOpen ? 'warn' : 'bad'), $curl ? '' : '将回退到 allow_url_fopen');
    $add('allow_url_fopen', $urlOpen ? 'On' : 'Off', $urlOpen ? 'good' : ($curl ? 'warn' : 'bad'), '');

    foreach (array('mbstring', 'fileinfo', 'openssl', 'gd', 'iconv') as $ext) {
        $loaded = extension_loaded($ext);
        $add($ext, $loaded ? 'enabled' : 'missing', $loaded ? 'good' : ($ext === 'openssl' ? 'bad' : 'warn'), '');
    }

    $add('session', session_id() !== '' ? 'active' : 'inactive', session_id() !== '' ? 'good' : 'bad', '');

    $upload = ini_bytes('upload_max_filesize');
    $post = ini_bytes('post_max_size');
    $limit = min($upload > 0 ? $upload : PHP_INT_MAX, $post > 0 ? $post : PHP_INT_MAX);
    $add('upload_max_filesize', ini_get('upload_max_filesize'), 'good', '');
    $add('post_max_size', ini_get('post_max_size'), 'good', '');
    $add('effective upload limit', $limit === PHP_INT_MAX ? 'unlimited' : human_size($limit), $limit >= 8 * 1024 * 1024 ? 'good' : 'warn', $limit < 8 * 1024 * 1024 ? '上传大文件可能失败' : '');

    $add('memory_limit', (string) ini_get('memory_limit'), ini_bytes('memory_limit') >= 128 * 1024 * 1024 || ini_get('memory_limit') === '-1' ? 'good' : 'warn', '');
    $add('max_execution_time', (string) ini_get('max_execution_time'), (int) ini_get('max_execution_time') === 0 || (int) ini_get('max_execution_time') >= 30 ? 'good' : 'warn', '');

    $root = root_dir();
    $add('document root', $root, 'good', '');
    $add('root writable', is_writable($root) ? 'yes' : 'no', is_writable($root) ? 'good' : 'bad', is_writable($root) ? '' : '根目录不可写，无法新建或上传');
    $storeWritable = @is_writable(XIAZZI_FILE);
    $add('data store', 'inline', 'good', '设置内嵌在本文件中，不产生外部配置文件');
    $add('data writable', $storeWritable ? 'yes' : 'no', $storeWritable ? 'good' : 'warn', $storeWritable ? '' : '设置无法保存，请给本文件写权限（chmod 644 或 664）');
    $permProbe = stat_bits(XIAZZI_FILE);
    $canPerm = ($permProbe['mode'] !== null);
    $add('perm source', $canPerm ? (xz_fn_ok('stat') ? 'stat' : 'fileperms') : 'unavailable', $canPerm ? 'good' : 'bad', $canPerm ? '' : '权限位读不出来，详情中的权限会显示为空');
    $canUser = ($permProbe['uid'] !== null) && (user_name_of_id($permProbe['uid']) !== '' || xz_fn_ok('posix_getpwuid') || @is_readable('/etc/passwd'));
    $add('owner source', xz_fn_ok('posix_getpwuid') ? 'posix' : (@is_readable('/etc/passwd') ? '/etc/passwd' : (xz_fn_ok('fileowner') ? 'uid' : 'unavailable')), $canUser ? 'good' : 'warn', $canUser ? '' : '无法取得拥有者，详情中的拥有者会显示为空');

    $storage = storage_info();
    if (!empty($storage['known'])) {
        $add('disk free', $storage['freeText'] . ' / ' . $storage['totalText'], $storage['free'] > 100 * 1024 * 1024 ? 'good' : 'warn', '');
    }

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $add('HTTPS', $https ? 'on' : 'off', $https ? 'good' : 'warn', $https ? '' : '公网部署建议启用 HTTPS');
    $add('server', isset($_SERVER['SERVER_SOFTWARE']) ? (string) $_SERVER['SERVER_SOFTWARE'] : PHP_SAPI, 'good', '');
    $add('OS', PHP_OS . ' / ' . php_uname('m'), 'good', '');
    $add('max upload (app)', (int) $GLOBALS['CONFIG']['max_upload_mb'] . ' MB', 'good', '');

    return env_row();
}

/* ------------------------------ 错误本地化 ------------------------------ */

function localize_error($msg) 
{
    $lang = current_lang();
    if ($lang === 'zh-CN') {
        return $msg;
    }
    $map = array(
        '没有选中任何项目' => array('No items selected', '未選取任何項目'),
        '该目录没有写入权限' => array('This folder is not writable', '此資料夾沒有寫入權限'),
        '当前目录没有写入权限' => array('This folder is not writable', '目前資料夾沒有寫入權限'),
        '目标文件夹没有写入权限' => array('Destination folder is not writable', '目標資料夾沒有寫入權限'),
        '目标不是文件夹' => array('Destination is not a folder', '目標不是資料夾'),
        '不是文件夹' => array('Not a folder', '不是資料夾'),
        '没有收到文件' => array('No file received', '沒有收到檔案'),
        '同名项目已存在' => array('An item with this name already exists', '同名項目已存在'),
        '不能重命名根目录' => array('The root folder cannot be renamed', '不能重新命名根目錄'),
        '不能移动到自身内部' => array('Cannot move a folder into itself', '不能移動到自身內部'),
        '源与目标相同' => array('Source and destination are the same', '來源與目標相同'),
        '写入失败' => array('Write failed', '寫入失敗'),
        '只支持 zip 与 tar.gz 格式' => array('Only zip and tar.gz are supported', '僅支援 zip 與 tar.gz 格式'),
        '压缩包为空或格式不受支持' => array('Archive is empty or unsupported', '壓縮檔為空或格式不受支援'),
        '无法创建解压目录' => array('Cannot create the target folder', '無法建立解壓縮目錄'),
        '不是文件' => array('Not a file', '不是檔案'),
        '文件不可写' => array('File is not writable', '檔案不可寫入'),
        '保存失败，请检查权限' => array('Save failed, check permissions', '儲存失敗，請檢查權限'),
        '页面已过期，请刷新后重试' => array('Page expired, please refresh', '頁面已過期，請重新整理'),
        '登录状态已失效，请重新登录' => array('Session expired, please sign in again', '登入狀態已失效，請重新登入'),
        '链接已过期' => array('This link has expired', '連結已過期'),
        '链接无效' => array('Invalid link', '連結無效'),
        '服务器内部错误' => array('Internal server error', '伺服器內部錯誤'),
        '未知操作' => array('Unknown operation', '未知操作'),
        '该后缀被禁止' => array('This file extension is blocked', '此副檔名被禁止'),
        '不支持的压缩格式' => array('Unsupported archive format', '不支援的壓縮格式'),
        '无法读取压缩包' => array('Cannot read the archive', '無法讀取壓縮檔'),
        '当前密码不正确' => array('Current password is incorrect', '目前密碼不正確'),
        '只支持 http / https 链接' => array('Only http / https links are supported', '僅支援 http / https 連結'),
        '无法创建压缩包' => array('Cannot create the archive', '無法建立壓縮檔'),
        '保存 zip 文件失败' => array('Cannot save the zip file', '儲存 zip 檔案失敗'),
        '不是 ZIP 压缩包' => array('Not a ZIP archive', '不是 ZIP 壓縮檔'),
        '不是有效的 ZIP 文件' => array('Not a valid ZIP file', '不是有效的 ZIP 檔案'),
        '压缩包结构损坏' => array('The archive is damaged', '壓縮檔結構損壞'),
        '压缩包内未找到该文件' => array('This file was not found in the archive', '壓縮檔內找不到該檔案'),
        '该文件已加密，无法预览' => array('This file is encrypted and cannot be previewed', '該檔案已加密，無法預覽'),
        '该压缩方式暂不支持预览' => array('This compression method is not supported for preview', '此壓縮方式暫不支援預覽'),
        '文件过大，无法在线预览' => array('File is too large to preview online', '檔案過大，無法線上預覽'),
        '压缩包内容读取失败' => array('Cannot read the file inside the archive', '讀取壓縮檔內容失敗'),
        '压缩包内容校验失败' => array('The file failed the CRC check', '壓縮檔內容校驗失敗'),
        '该文件不是文本，无法预览' => array('This is not a text file', '該檔案不是文字檔'),
        '无法识别该文件的文本编码' => array('Cannot detect the text encoding', '無法辨識該檔案的文字編碼'),
    );
    $key = preg_replace('/（.*$/u', '', $msg);
    foreach ($map as $zh => $pair) {
        if ($msg === $zh || $key === $zh) {
            return $lang === 'zh-TW' ? $pair[1] : $pair[0];
        }
    }
    return $msg;
}

/* ------------------------------ 接口实现 ------------------------------ */

function handle_api($api) 
{
    global $CONFIG;

    if ($api === 'login') {
        $user = trim((string) param('user', ''));
        $pass = (string) param('pass', '');
        if ($user === '' && auth_enabled()) {
            $user = effective_user();
        }
        $fails = isset($_SESSION['login_fails']) ? (int) $_SESSION['login_fails'] : 0;
        if ($fails >= 5) {
            sleep(1);
        }
        $userOk = !auth_enabled() ? true : hash_equals(effective_user(), $user);
        $passOk = !auth_enabled() ? true : verify_password($pass);
        if (!$userOk || !$passOk) {
            $_SESSION['login_fails'] = $fails + 1;
            usleep(350000);
            api_fail(t('bad_login'), 401);
        }
        $remember = (string) param('remember', '') === '1';
        $csrf = begin_login_session(effective_user(), $remember);
        json_out(array('ok' => true, 'csrf' => $csrf, 'setup' => setup_required()));
    }

    /* 首次使用引导：设置管理员账号与密码，成功后自动登录。
     * 程序不内置默认密码，因此这里不校验「当前密码」，
     * 只做 CSRF 校验与新账号、新密码的合法性校验。 */
    if ($api === 'setup') {
        if (!setup_required()) {
            api_fail(t('setup_done_already'), 409);
        }
        require_csrf();

        $user = trim((string) param('user', ''));
        $pass = (string) param('pass', '');
        $pass2 = (string) param('pass2', '');

        check_admin_user($user);
        check_new_password($pass, $user);
        if ($pass !== $pass2) {
            api_fail(t('setup_err_pass2'), 400);
        }

        // 一次写入：账号、密码哈希、完成标记，并轮换记住登录密钥（旧令牌全部失效）
        $ok = settings_write(array(
            'user'            => $user,
            'pass_hash'       => password_hash($pass, PASSWORD_DEFAULT),
            'setup_done'      => true,
            'setup_at'        => time(),
            'remember_secret' => bin2hex(random_bytes(24)),
        ));
        if (!$ok) {
            api_fail(t('setup_err_save'), 500);
        }

        // 首次设置完成：丢弃可能存在的旧登录态与自动登录令牌
        clear_remember_cookie();
        $remember = (string) param('remember', '1') !== '0';
        $csrf = begin_login_session($user, $remember);
        json_out(array('ok' => true, 'user' => $user, 'csrf' => $csrf, 'csrf_token' => $csrf));
    }

    if ($api === 'logout') {
        destroy_auth_session(false);
        json_out(array('ok' => true));
    }

    if ($api === 'download' || $api === 'raw') {
        require_login();
        serve_file((string) param('path', ''), $api === 'raw');
    }

    if ($api === 'hls') {
        require_login();
        serve_hls((string) param('path', ''));
    }

    if ($api === 'zip_raw') {
        require_login();
        $abs = resolve_path((string) param('path', ''));
        if (!is_file($abs)) {
            api_fail('不是文件', 404);
        }
        if (ext_of($abs) !== 'zip') {
            api_fail('不是 ZIP 压缩包');
        }
        serve_zip_entry($abs, (int) param('i', -1), (string) param('dl', '') === '1');
    }

    if ($api === 'share_open') {
        $rel = parse_link((string) param('t', ''));
        serve_file($rel, true);
    }

    require_login();
    require_csrf();

    switch ($api) {
        case 'boot':
            json_out(array('ok' => true, 'data' => boot_data()));
            break;

        case 'list':
            json_out(array('ok' => true, 'data' => list_items((string) param('path', '')), 'storage' => storage_info()));
            break;

        case 'storage':
            json_out(array('ok' => true, 'data' => storage_info()));
            break;

        case 'dirstat':
            json_out(array('ok' => true, 'data' => dir_stats((string) param('path', ''))));
            break;

        case 'stat':
            $paths = param('paths', array());
            $paths = is_array($paths) ? $paths : array();
            $result = array();
            foreach ($paths as $path) {
                try {
                    $abs = resolve_path((string) $path);
                    if (file_exists($abs) && rel_path($abs) !== '') {
                        $result[] = item_of($abs, array('perms' => (bool) setting('show_perms', false)));
                    }
                } catch (ApiException $e) {
                    continue;
                }
            }
            json_out(array('ok' => true, 'items' => $result));
            break;

        case 'info':
            $relReq = trim(str_replace('\\', '/', (string) param('path', '')), '/');
            $abs = resolve_path($relReq);
            $rawAbs = ($relReq === '') ? $abs : join_rel($relReq);
            $item = item_of($abs, array('perms' => true), $rawAbs);
            /* 符号链接：resolve_path 会把路径归到目标文件上，详情里应显示链接
               自身的名称与路径，权限列同样取链接本身（lrwxrwxrwx） */
            if ($relReq !== '' && is_link_path($rawAbs)) {
                $item['name'] = basename($relReq);
                $item['path'] = $relReq;
            }
            $item['readable'] = is_readable($abs) ? 1 : 0;
            $item['writable'] = is_writable($abs) ? 1 : 0;
            $item['mime'] = is_dir($abs) ? 'inode/directory' : mime_of(ext_of($abs));
            $item['link'] = is_dir($abs) ? '' : direct_url(rel_path($abs));
            /* 列表接口里文件夹的 size 恒为 0，详情面板因此显示「—」。
               这里对文件夹单独做一次递归统计，把真实占用大小与子项数量补上 */
            if (!empty($item['dir']) && is_readable($abs)) {
                $dst = dir_stats_abs($abs);
                $item['size'] = $dst['size'];
                $item['sizeText'] = human_size($dst['size']);
                $item['subFiles'] = $dst['files'];
                $item['subDirs'] = $dst['dirs'];
                $item['sizePartial'] = $dst['partial'];
            }
            json_out(array('ok' => true, 'item' => $item));
            break;

        case 'recent':
            $base = resolve_path((string) param('path', ''));
            if (!is_dir($base)) {
                $base = root_dir();
            }
            $items = walk_files($base, '', 400, false);
            usort($items, 'cmp_mtime_desc');
            json_out(array('ok' => true, 'items' => array_slice($items, 0, 60)));
            break;

        case 'search':
            $q = trim((string) param('q', ''));
            if ($q === '') {
                json_out(array('ok' => true, 'items' => array()));
            }
            $base = resolve_path((string) param('path', ''));
            if (!is_dir($base)) {
                $base = root_dir();
            }
            json_out(array('ok' => true, 'items' => walk_files($base, $q, 200, true)));
            break;

        case 'mkdir':
            $dir = resolve_path((string) param('path', ''));
            $name = check_name((string) param('name', ''));
            if (!is_dir($dir)) {
                api_fail('目标不是文件夹');
            }
            if (!is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $target = unique_path($dir, $name);
            if (!@mkdir($target, 0755)) {
                api_fail('创建失败，请检查目录权限');
            }
            json_out(array('ok' => true, 'item' => item_of($target), 'name' => basename($target)));
            break;

        case 'newfile':
            $dir = resolve_path((string) param('path', ''));
            $name = check_name((string) param('name', 'untitled.txt'));
            if (blocked_ext($name)) {
                api_fail('出于安全考虑，不允许创建该类型的文件');
            }
            if (!is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $target = unique_path($dir, $name);
            $handle = @fopen($target, 'x');
            if ($handle === false) {
                api_fail('创建失败，请检查目录权限');
            }
            fclose($handle);
            @chmod($target, 0644);
            json_out(array('ok' => true, 'item' => item_of($target)));
            break;

        case 'rename':
            $abs = resolve_path((string) param('path', ''));
            if (rel_path($abs) === '') {
                api_fail('不能重命名根目录', 403);
            }
            $name = check_name((string) param('name', ''));
            if (blocked_ext($name)) {
                api_fail('出于安全考虑，不允许使用该后缀');
            }
            $target = dirname($abs) . '/' . $name;
            if (file_exists($target) && $target !== $abs) {
                api_fail('同名项目已存在');
            }
            if (!@rename($abs, $target)) {
                api_fail('重命名失败，请检查权限');
            }
            json_out(array('ok' => true, 'item' => item_of($target)));
            break;

        case 'delete':
            $paths = param('paths', array());
            $paths = is_array($paths) ? $paths : array();
            if (count($paths) === 0) {
                api_fail('没有选中任何项目');
            }
            $okCount = 0;
            $failed = array();
            foreach ($paths as $path) {
                try {
                    $abs = resolve_path((string) $path);
                    if (rel_path($abs) === '') {
                        $failed[] = basename($abs);
                        continue;
                    }
                    if (remove_recursive($abs)) {
                        $okCount++;
                    } else {
                        $failed[] = basename($abs);
                    }
                } catch (ApiException $e) {
                    $failed[] = basename((string) $path);
                }
            }
            json_out(array('ok' => true, 'deleted' => $okCount, 'failed' => $failed));
            break;

        case 'copy':
        case 'move':
            $paths = param('paths', array());
            $paths = is_array($paths) ? $paths : array();
            $destRel = (string) param('dest', '');
            $dest = resolve_path($destRel);
            if (!is_dir($dest)) {
                api_fail('目标不是文件夹');
            }
            if (!is_writable($dest)) {
                api_fail('目标文件夹没有写入权限', 403);
            }
            $done = array();
            $failed = array();
            foreach ($paths as $path) {
                try {
                    $src = resolve_path((string) $path);
                    if (rel_path($src) === '') {
                        $failed[] = basename($src);
                        continue;
                    }
                    $destAbs = str_replace('\\', '/', $dest);
                    $srcAbs = str_replace('\\', '/', $src);
                    if ($destAbs === $srcAbs) {
                        $failed[] = basename($src) . '（源与目标相同）';
                        continue;
                    }
                    if (is_dir($src) && strpos($destAbs . '/', $srcAbs . '/') === 0) {
                        $failed[] = basename($src) . '（不能移动到自身内部）';
                        continue;
                    }
                    $target = unique_path($dest, basename($src));
                    $ok = $api === 'move' ? @rename($src, $target) : copy_recursive($src, $target);
                    if (!$ok) {
                        $failed[] = basename($src) . '（写入失败）';
                        continue;
                    }
                    $done[] = basename($target);
                } catch (ApiException $e) {
                    $failed[] = basename((string) $path);
                }
            }
            json_out(array('ok' => true, 'done' => $done, 'failed' => $failed));
            break;

        case 'compress':
            $paths = param('paths', array());
            $paths = is_array($paths) ? $paths : array();
            if (count($paths) === 0) {
                api_fail('没有选中任何项目');
            }
            $format = (string) param('format', 'zip');
            if ($format !== 'zip' && $format !== 'tar.gz') {
                api_fail('不支持的压缩格式');
            }
            $destRel = (string) param('dest', '');
            if ($destRel === '') {
                $first = (string) $paths[0];
                $slash = strrpos($first, '/');
                $destRel = $slash === false ? '' : substr($first, 0, $slash);
            }
            $dir = resolve_path($destRel);
            if (!is_dir($dir)) {
                api_fail('目标不是文件夹');
            }
            if (!is_writable($dir)) {
                api_fail('当前目录没有写入权限', 403);
            }
            $name = trim((string) param('name', ''));
            if ($name === '') {
                $name = count($paths) === 1 ? pathinfo((string) $paths[0], PATHINFO_FILENAME) : 'archive';
                if (ext_of((string) $paths[0]) === 'tar.gz' && count($paths) === 1) {
                    $name = substr(basename((string) $paths[0]), 0, -7);
                }
            }
            $level = (int) param('level', 6);
            if ($level < 0 || $level > 9) {
                $level = 6;
            }
            $target = compress_to($dir, $format, $paths, $name, $level);
            json_out(array('ok' => true, 'item' => item_of($target), 'name' => basename($target)));
            break;

        case 'extract':
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('只能解压文件');
            }
            $ext = ext_of($abs);
            if ($ext !== 'zip' && $ext !== 'tar.gz' && $ext !== 'tgz' && $ext !== 'gz') {
                api_fail('只支持 zip 与 tar.gz 格式');
            }
            /* 解压模式：here = 直接释放到当前目录；folder = 生成独立文件夹 */
            $mode = (string) param('mode', 'folder');
            if ($mode !== 'here' && $mode !== 'folder') {
                $mode = 'folder';
            }
            $destParam = trim((string) param('dest', ''));
            $dir = $destParam !== '' ? resolve_path($destParam) : dirname($abs);
            if (!is_dir($dir)) {
                api_fail('目标不是文件夹');
            }
            if (!is_writable($dir)) {
                api_fail('当前目录没有写入权限', 403);
            }
            $base = basename($abs);
            $folderName = preg_replace('/\.(tar\.gz|tgz|gz|zip)$/i', '', $base);
            $folderName = $folderName === '' ? 'extracted' : $folderName;
            $customName = trim((string) param('name', ''));
            if ($mode === 'folder' && $customName !== '') {
                /* 只允许单层目录名，剔除路径分隔符与系统保留字符 */
                $customName = str_replace(array('\\', '/', "\0", ':', '*', '?', '"', '<', '>', '|'), '', $customName);
                $customName = trim($customName, " .\t\n\r");
                if ($customName !== '' && $customName !== '.' && $customName !== '..') {
                    $folderName = $customName;
                }
            }
            if ($mode === 'here') {
                $folder = $dir;
            } else {
                $folder = unique_path($dir, $folderName);
                if (!@mkdir($folder, 0755)) {
                    api_fail('无法创建解压目录');
                }
            }
            try {
                $dedupe = ($mode === 'here');
                if ($ext === 'zip') {
                    $result = zip_extract($abs, $folder, '', $dedupe);
                } else {
                    $result = tar_extract_gz($abs, $folder, '', $dedupe);
                }
            } catch (Exception $e) {
                if ($mode !== 'here') {
                    remove_recursive($folder);
                }
                throw $e;
            }
            if ((int) $result['count'] === 0) {
                if ($mode !== 'here') {
                    remove_recursive($folder);
                }
                api_fail('压缩包为空或格式不受支持');
            }
            json_out(array(
                'ok'     => true,
                'mode'   => $mode,
                'folder' => rel_path($folder),
                'name'   => basename($folder),
                'count'  => (int) $result['count']
            ));
            break;

        case 'zip_list':
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('不是文件');
            }
            if (ext_of($abs) !== 'zip') {
                api_fail('不是 ZIP 压缩包');
            }
            $idx = zip_index($abs, 5000);
            $list = array();
            foreach ($idx['entries'] as $entry) {
                $list[] = array(
                    'i'      => (int) $entry['i'],
                    'name'   => $entry['name'],
                    'dir'    => $entry['dir'],
                    'size'   => (int) $entry['size'],
                    'csize'  => (int) $entry['csize'],
                    'mtime'  => (int) $entry['mtime'],
                    'locked' => $entry['locked'],
                );
            }
            json_out(array(
                'ok'        => true,
                'name'      => basename($abs),
                'size'      => (int) @filesize($abs),
                'total'     => (int) $idx['total'],
                'files'     => (int) $idx['files'],
                'folders'   => (int) $idx['folders'],
                'bytes'     => (float) $idx['bytes'],
                'truncated' => (bool) $idx['truncated'],
                'entries'   => $list,
            ));
            break;

        case 'zip_read':
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('不是文件');
            }
            if (ext_of($abs) !== 'zip') {
                api_fail('不是 ZIP 压缩包');
            }
            $res = xz_zip_entry_read($abs, (int) param('i', -1), 4194304);
            $encoding = 'utf-8';
            $content = decode_text($res['data'], 'auto', $encoding);
            if (strpos($content, "\0") !== false) {
                api_fail('该文件不是文本，无法预览');
            }
            if ($content !== '' && !preg_match('//u', $content)) {
                api_fail('无法识别该文件的文本编码');
            }
            json_out(array(
                'ok'       => true,
                'name'     => $res['entry']['name'],
                'content'  => $content,
                'size'     => strlen($res['data']),
                'encoding' => $encoding,
            ));
            break;

        case 'read':
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('不是文件');
            }
            $size = (int) filesize($abs);
            if ($size > 5 * 1024 * 1024) {
                api_fail('文件超过 5MB，无法在线编辑');
            }
            $raw = (string) file_get_contents($abs);
            $enc = normalize_encoding((string) param('encoding', 'auto'));
            $detected = 'utf-8';
            $content = decode_text($raw, $enc, $detected);
            if ($content !== '' && !preg_match('//u', $content)) {
                api_fail('无法识别该文件的文本编码，请在编辑器中手动选择编码后重试');
            }
            $ext = ext_of($abs);
            json_out(array(
                'ok'       => true,
                'content'  => $content,
                'name'     => basename($abs),
                'size'     => $size,
                'ext'      => $ext,
                'encoding' => $detected,
                'has_bom'  => substr($raw, 0, 3) === "\xEF\xBB\xBF" ? 1 : 0,
                'editable' => in_array($ext, $CONFIG['edit_ext'], true) && is_writable($abs),
                'path'     => rel_path($abs),
            ));
            break;

        case 'save':
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('不是文件');
            }
            if (!is_writable($abs)) {
                api_fail('文件不可写', 403);
            }
            $content = (string) param('content', '');
            if (strlen($content) > 16 * 1024 * 1024) {
                api_fail('内容超过 16MB');
            }
            $encRaw = trim((string) param('encoding', 'auto'));
            $withBom = ((string) param('bom', '0') === '1') || $encRaw === 'utf-8bom' || $encRaw === 'utf8bom';
            $enc = normalize_encoding($encRaw);
            $err = '';
            $bytes = encode_for_disk($content, $enc, $withBom, $err);
            if ($bytes === false) {
                api_fail($err);
            }
            if (@file_put_contents($abs, $bytes, LOCK_EX) === false) {
                api_fail('保存失败，请检查权限');
            }
            json_out(array('ok' => true, 'size' => strlen($bytes), 'encoding' => $enc, 'has_bom' => $withBom ? 1 : 0));
            break;

        case 'upload':
            $path = (string) param('path', '');
            $dir = resolve_path($path);
            if (!is_dir($dir)) {
                api_fail('目标不是文件夹');
            }
            if (!is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            if (!isset($_FILES['files'])) {
                $len = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
                $postMax = ini_bytes('post_max_size');
                if ($len > 0 && $postMax > 0 && $len > $postMax) {
                    api_fail('文件超过服务器接收上限（post_max_size = ' . ini_get('post_max_size') . '），请调小文件或联系主机商');
                }
                api_fail('没有收到文件');
            }
            xz_extend_time(600);
            $files = $_FILES['files'];
            $names = is_array($files['name']) ? $files['name'] : array($files['name']);
            $tmps = is_array($files['tmp_name']) ? $files['tmp_name'] : array($files['tmp_name']);
            $errors = is_array($files['error']) ? $files['error'] : array($files['error']);
            $sizes = is_array($files['size']) ? $files['size'] : array($files['size']);
            $rels = param('rels', array());
            $rels = is_array($rels) ? $rels : array();
            $limit = (int) $CONFIG['max_upload_mb'] * 1024 * 1024;
            /* 应用上限不能超过服务器 upload_max_filesize / post_max_size，否则永远传不上去 */
            $iniUp = ini_bytes('upload_max_filesize');
            $iniPost = ini_bytes('post_max_size');
            if ($iniUp > 0 && $iniUp < $limit) {
                $limit = $iniUp;
            }
            if ($iniPost > 0 && $iniPost < $limit) {
                $limit = $iniPost;
            }
            $saved = array();
            $failed = array();
            foreach ($names as $index => $rawName) {
                $error = (int) $errors[$index];
                if ($error === UPLOAD_ERR_NO_FILE) {
                    continue;
                }
                $safeName = basename(str_replace('\\', '/', (string) $rawName));
                if ($error !== UPLOAD_ERR_OK) {
                    $failed[] = $safeName . '（上传中断）';
                    continue;
                }
                try {
                    $safeName = check_name($safeName);
                } catch (ApiException $e) {
                    $failed[] = (string) $rawName . '（名称不合法）';
                    continue;
                }
                if (blocked_ext($safeName)) {
                    $failed[] = $safeName . '（该后缀被禁止）';
                    continue;
                }
                if ((int) $sizes[$index] > $limit) {
                    $failed[] = $safeName . '（超过 ' . human_size($limit) . '）';
                    continue;
                }
                $targetDir = $dir;
                if (isset($rels[$index]) && (string) $rels[$index] !== '') {
                    $relDir = dirname(str_replace('\\', '/', (string) $rels[$index]));
                    if ($relDir !== '.' && $relDir !== '') {
                        $pieces = explode('/', $relDir);
                        foreach ($pieces as $piece) {
                            if ($piece === '' || $piece === '.' || $piece === '..') {
                                continue 2;
                            }
                            $targetDir .= '/' . $piece;
                        }
                        if (!is_dir($targetDir) && !@mkdir($targetDir, 0755, true)) {
                            $failed[] = $safeName . '（目录创建失败）';
                            continue;
                        }
                    }
                }
                $target = unique_path($targetDir, $safeName);
                if (!@move_uploaded_file((string) $tmps[$index], $target)) {
                    $failed[] = $safeName . '（写入失败）';
                    continue;
                }
                @chmod($target, 0644);
                $saved[] = $safeName;
            }
            if (count($saved) === 0 && count($failed) > 0) {
                api_fail(implode('、', $failed));
            }
            json_out(array('ok' => true, 'saved' => $saved, 'failed' => $failed));
            break;

        case 'save_base64':
            // 供移动端「粘贴剪贴板图片」等场景使用
            $dir = resolve_path((string) param('path', ''));
            if (!is_dir($dir) || !is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $data = (string) param('data', '');
            $name = check_name((string) param('name', 'image.png'));
            if (!preg_match('#^data:([a-z0-9.+/-]+);base64,(.+)$#i', $data, $m)) {
                api_fail('数据格式不正确');
            }
            $bin = base64_decode($m[2], true);
            if ($bin === false) {
                api_fail('数据解码失败');
            }
            if (strlen($bin) > 32 * 1024 * 1024) {
                api_fail('文件超过 32MB');
            }
            $target = unique_path($dir, $name);
            if (@file_put_contents($target, $bin) === false) {
                api_fail('写入失败');
            }
            @chmod($target, 0644);
            json_out(array('ok' => true, 'item' => item_of($target)));
            break;

        case 'url_download':
            $url = trim((string) param('url', ''));
            if (!preg_match('#^https?://#i', $url)) {
                api_fail('只支持 http / https 链接');
            }
            $dir = resolve_path((string) param('path', ''));
            if (!is_dir($dir) || !is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $name = trim((string) param('name', ''));
            if ($name === '') {
                $name = filename_from_url($url);
            }
            try {
                $name = check_name($name);
            } catch (ApiException $e) {
                $name = 'download-' . date('YmdHis') . '.bin';
            }
            if (blocked_ext($name)) {
                api_fail('该后缀被禁止保存');
            }
            $target = unique_path($dir, $name);
            $res = http_request($url, array('timeout' => 120, 'save_to' => $target, 'max_bytes' => 1024 * 1024 * 1024));
            if (!$res['ok']) {
                @unlink($target);
                api_fail('下载失败：' . ($res['error'] !== '' ? $res['error'] : '无法连接'));
            }
            if (!is_file($target) || filesize($target) === 0) {
                @unlink($target);
                api_fail('下载失败：文件为空');
            }
            @chmod($target, 0644);
            json_out(array('ok' => true, 'item' => item_of($target), 'name' => basename($target)));
            break;

        case 'github_refs':
            $repo = parse_repo((string) param('repo', ''));
            $apiRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'], $repo['token']);
            if (!$apiRes['ok']) {
                api_fail('无法读取仓库：' . $apiRes['error']);
            }
            $info = json_decode($apiRes['body'], true);
            if (!is_array($info)) {
                api_fail('仓库信息解析失败');
            }
            $full = isset($info['full_name']) ? (string) $info['full_name'] : $repo['owner'] . '/' . $repo['name'];
            $branches = array();
            $tags = array();
            $bRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'] . '/branches?per_page=100', $repo['token']);
            if ($bRes['ok']) {
                $list = json_decode($bRes['body'], true);
                if (is_array($list)) {
                    foreach ($list as $row) {
                        if (isset($row['name'])) {
                            $branches[] = array(
                                'name' => (string) $row['name'],
                                'sha'  => isset($row['commit']['sha']) ? (string) $row['commit']['sha'] : '',
                                'date' => isset($row['commit']['commit']['author']['date']) ? (string) $row['commit']['commit']['author']['date'] : '',
                                'note' => isset($row['commit']['commit']['message']) ? gh_cut(gh_strip_md((string) $row['commit']['commit']['message']), 90) : '',
                            );
                        }
                    }
                }
            }
            /* 发行版：给出每个标签的名称、发布日期与发行说明，用于「其他版本介绍」 */
            $releaseMap = array();
            $releases = array();
            $rRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'] . '/releases?per_page=30', $repo['token']);
            if ($rRes['ok']) {
                $list = json_decode($rRes['body'], true);
                if (is_array($list)) {
                    foreach ($list as $row) {
                        if (empty($row['tag_name']) || !empty($row['draft'])) {
                            continue;
                        }
                        $rel = array(
                            'tag'   => (string) $row['tag_name'],
                            'name'  => isset($row['name']) ? (string) $row['name'] : '',
                            'date'  => isset($row['published_at']) ? (string) $row['published_at'] : (isset($row['created_at']) ? (string) $row['created_at'] : ''),
                            'body'  => isset($row['body']) ? gh_cut(gh_strip_md((string) $row['body']), 420) : '',
                            'pre'   => !empty($row['prerelease']),
                            'url'   => isset($row['html_url']) ? (string) $row['html_url'] : '',
                        );
                        $releases[] = $rel;
                        $releaseMap[$rel['tag']] = $rel;
                    }
                }
            }
            $tRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'] . '/tags?per_page=100', $repo['token']);
            if ($tRes['ok']) {
                $list = json_decode($tRes['body'], true);
                if (is_array($list)) {
                    foreach ($list as $row) {
                        if (!isset($row['name'])) {
                            continue;
                        }
                        $tagName = (string) $row['name'];
                        $rel = isset($releaseMap[$tagName]) ? $releaseMap[$tagName] : null;
                        $tags[] = array(
                            'name'  => $tagName,
                            'sha'   => isset($row['commit']['sha']) ? (string) $row['commit']['sha'] : '',
                            'date'  => $rel ? $rel['date'] : '',
                            'note'  => $rel ? ($rel['body'] !== '' ? $rel['body'] : $rel['name']) : '',
                            'title' => $rel ? $rel['name'] : '',
                            'pre'   => $rel ? $rel['pre'] : false,
                            'url'   => $rel ? $rel['url'] : '',
                            'has_rel' => $rel !== null,
                        );
                    }
                }
            }
            /* README 摘要作为功能介绍；失败时退化为仓库简介 */
            $intro = '';
            $readmeRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'] . '/readme', $repo['token'], 'application/vnd.github.raw');
            if ($readmeRes['ok'] && is_string($readmeRes['body'])) {
                $intro = gh_readme_summary((string) $readmeRes['body'], 300);
            }
            $lic = '';
            if (!empty($info['license']['spdx_id'])) {
                $lic = (string) $info['license']['spdx_id'];
            } elseif (!empty($info['license']['name'])) {
                $lic = (string) $info['license']['name'];
            }
            $topics = array();
            if (isset($info['topics']) && is_array($info['topics'])) {
                foreach (array_slice($info['topics'], 0, 8) as $t) {
                    $topics[] = (string) $t;
                }
            }
            $latest = null;
            foreach ($releases as $rel) {
                if (empty($rel['pre'])) {
                    $latest = $rel;
                    break;
                }
            }
            if ($latest === null && !empty($releases)) {
                $latest = $releases[0];
            }
            /* zip 体积：GitHub 不提供压缩包精确大小，按仓库体积估算，前端标注「约」 */
            $repoKb = isset($info['size']) ? (int) $info['size'] : 0;
            $zipEst = $repoKb > 0 ? (int) round($repoKb * 1024 * 0.85) : 0;
            foreach ($branches as $bk => $bv) {
                $branches[$bk]['zip_size'] = $zipEst;
            }
            foreach ($tags as $tk => $tv) {
                $tags[$tk]['zip_size'] = $zipEst;
            }
            json_out(array(
                'ok' => true,
                'zip_size' => $zipEst,
                'repo' => $full,
                'default' => isset($info['default_branch']) ? (string) $info['default_branch'] : 'main',
                'desc' => isset($info['description']) ? (string) $info['description'] : '',
                'stars' => isset($info['stargazers_count']) ? (int) $info['stargazers_count'] : 0,
                'forks' => isset($info['forks_count']) ? (int) $info['forks_count'] : 0,
                'issues' => isset($info['open_issues_count']) ? (int) $info['open_issues_count'] : 0,
                'private' => !empty($info['private']),
                'archived' => !empty($info['archived']),
                'lang' => isset($info['language']) ? (string) $info['language'] : '',
                'license' => $lic,
                'topics' => $topics,
                'homepage' => isset($info['homepage']) ? (string) $info['homepage'] : '',
                'updated' => isset($info['pushed_at']) ? (string) $info['pushed_at'] : (isset($info['updated_at']) ? (string) $info['updated_at'] : ''),
                'url' => isset($info['html_url']) ? (string) $info['html_url'] : 'https://github.com/' . $full,
                'size' => isset($info['size']) ? (int) $info['size'] : 0,
                'intro' => $intro,
                'latest' => $latest,
                'release_count' => count($releases),
                'branches' => $branches,
                'tags' => $tags,
            ));
            break;

        case 'github_download':
            $repo = parse_repo((string) param('repo', ''));
            $ref = trim((string) param('ref', ''));
            $kind = (string) param('kind', 'branch');
            /* 未显式传 mode 时，按「设置 · 通用」里的 GitHub 下载方式决定（默认仅下载 zip） */
            $mode = param('mode', null);
            if ($mode === null || $mode === '') {
                $mode = setting('gh_extract', false) ? 'extract' : 'zip';
            }
            $mode = (string) $mode;
            if ($mode !== 'extract' && $mode !== 'zip') {
                $mode = 'zip';
            }
            $dir = resolve_path((string) param('path', ''));
            if (!is_dir($dir) || !is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $token = $repo['token'];
            $label = $ref !== '' ? $ref : 'default';
            if ($ref === '') {
                $apiRes = github_api('repos/' . $repo['owner'] . '/' . $repo['name'], $token);
                $info = $apiRes['ok'] ? json_decode($apiRes['body'], true) : null;
                $ref = is_array($info) && isset($info['default_branch']) ? (string) $info['default_branch'] : 'main';
                $label = $ref;
            }
            $tmpZip = $dir . '/.xiazzi-gh-' . bin2hex(random_bytes(4)) . '.zip';
            $urls = array();
            if ($kind === 'tag') {
                $urls[] = 'https://codeload.github.com/' . $repo['owner'] . '/' . $repo['name'] . '/zip/refs/tags/' . rawurlencode($ref);
            } elseif ($kind === 'commit') {
                $urls[] = 'https://codeload.github.com/' . $repo['owner'] . '/' . $repo['name'] . '/zip/' . rawurlencode($ref);
            } else {
                $urls[] = 'https://codeload.github.com/' . $repo['owner'] . '/' . $repo['name'] . '/zip/refs/heads/' . rawurlencode($ref);
            }
            $urls[] = 'https://api.github.com/repos/' . $repo['owner'] . '/' . $repo['name'] . '/zipball/' . rawurlencode($ref);
            $headers = array('User-Agent: EuPHPFileManager/' . XIAZZI_VERSION, 'Accept: application/vnd.github+json');
            if ($token !== '') {
                $headers[] = 'Authorization: token ' . $token;
            }
            $ok = false;
            $lastError = '';
            foreach ($urls as $url) {
                $res = http_request($url, array('timeout' => 300, 'save_to' => $tmpZip, 'headers' => $headers, 'max_bytes' => 1024 * 1024 * 1024));
                if ($res['ok'] && is_file($tmpZip) && filesize($tmpZip) > 0) {
                    $ok = true;
                    break;
                }
                $lastError = $res['error'];
                @unlink($tmpZip);
            }
            if (!$ok) {
                @unlink($tmpZip);
                api_fail('仓库下载失败：' . ($lastError !== '' ? $lastError : '未知错误'));
            }
            $safeRef = preg_replace('/[^A-Za-z0-9._-]/', '-', $label);
            $folderBase = $repo['name'] . ($safeRef !== '' ? '-' . $safeRef : '');

            /* 方式一：只保存 zip，不自动解压（默认） */
            if ($mode === 'zip') {
                $zipPath = unique_path($dir, $folderBase . '.zip');
                if (!@rename($tmpZip, $zipPath)) {
                    if (!@copy($tmpZip, $zipPath)) {
                        @unlink($tmpZip);
                        api_fail('保存 zip 文件失败');
                    }
                    @unlink($tmpZip);
                }
                @chmod($zipPath, 0644);
                clearstatcache(true, $zipPath);
                json_out(array(
                    'ok'        => true,
                    'mode'      => 'zip',
                    'extracted' => false,
                    'file'      => basename($zipPath),
                    'name'      => basename($zipPath),
                    'path'      => rel_path($zipPath),
                    'folder'    => '',
                    'size'      => (int) @filesize($zipPath),
                ));
            }

            $target = unique_path($dir, $folderBase);
            $tmpDir = $dir . '/.xiazzi-gh-' . bin2hex(random_bytes(4));
            if (!@mkdir($tmpDir, 0755)) {
                @unlink($tmpZip);
                api_fail('无法创建临时目录');
            }
            try {
                zip_extract($tmpZip, $tmpDir);
            } catch (Exception $e) {
                remove_recursive($tmpDir);
                @unlink($tmpZip);
                api_fail('解压仓库失败：' . $e->getMessage());
            }
            @unlink($tmpZip);
            $children = array_values(array_diff((array) @scandir($tmpDir), array('.', '..')));
            if (count($children) === 1 && is_dir($tmpDir . '/' . $children[0])) {
                if (!@rename($tmpDir . '/' . $children[0], $target)) {
                    remove_recursive($tmpDir);
                    api_fail('移动解压结果失败');
                }
                remove_recursive($tmpDir);
            } else {
                if (!@rename($tmpDir, $target)) {
                    remove_recursive($tmpDir);
                    api_fail('移动解压结果失败');
                }
            }
            json_out(array(
                'ok'        => true,
                'mode'      => 'extract',
                'extracted' => true,
                'folder'    => rel_path($target),
                'name'      => basename($target),
                'file'      => '',
                'path'      => rel_path($target),
            ));
            break;

        case 'link':
            $abs = resolve_path((string) param('path', ''));
            if (is_dir($abs)) {
                // 文件夹：简洁模式下为 {站点}/{文件夹}/，不带脚本名与参数
                json_out(array('ok' => true, 'url' => dir_url(rel_path($abs)), 'dir' => true));
            }
            json_out(array('ok' => true, 'url' => direct_url(rel_path($abs)), 'dir' => false));
            break;

        case 'settings_get':
            json_out(array('ok' => true, 'settings' => settings_public(), 'env' => null));
            break;

        case 'settings_save':
            $lang = (string) param('lang', setting('lang', 'zh-CN'));
            $langDict = i18n_dict();
            if (!isset($langDict[$lang])) {
                $lang = 'zh-CN';
            }
            $editor = (string) param('editor', 'normal');
            if ($editor !== 'normal' && $editor !== 'advanced') {
                $editor = 'normal';
            }
            $theme = (string) param('theme', 'system');
            if (!in_array($theme, array('system', 'light', 'dark'), true)) {
                $theme = 'system';
            }
            $linkStyle = strtolower(trim((string) param('link_style', 'pretty')));
            if ($linkStyle !== 'pretty' && $linkStyle !== 'param') {
                $linkStyle = 'pretty';
            }
            $patch = array(
                'link_style'  => $linkStyle,
                'lang'        => $lang,
                'editor'      => $editor,
                'theme'       => $theme,
                'show_hidden' => (bool) param('show_hidden', false),
                'show_perms'  => (bool) param('show_perms', false),
                'hide_self'   => (bool) param('hide_self', setting('hide_self', true)),
                'gh_extract'  => (bool) param('gh_extract', false),
            );
            if (param('gh_token', null) !== null) {
                $patch['gh_token'] = substr(trim((string) param('gh_token', '')), 0, 255);
            }
            if (!settings_write($patch)) {
                api_fail('设置保存失败，请检查目录写入权限');
            }
            json_out(array('ok' => true, 'settings' => settings_public(), 'env' => null));
            break;

        case 'password':
            $old = (string) param('old', '');
            $new = (string) param('new', '');
            if (!verify_password($old)) {
                api_fail('当前密码不正确', 403);
            }
            if (strlen($new) < 6) {
                api_fail(t('pass_short'));
            }
            if (strlen($new) > 200) {
                api_fail('密码过长');
            }
            if (!settings_write(array('pass_hash' => password_hash($new, PASSWORD_DEFAULT)))) {
                api_fail('密码保存失败，请检查目录权限');
            }
            // 密码已变更：立即退出登录并清除原有登录临时数据
            destroy_auth_session(true);
            json_out(array('ok' => true, 'logout' => true));
            break;

        case 'username':
            $oldPass = (string) param('pass', '');
            $newUser = trim((string) param('user', ''));
            if (!verify_password($oldPass)) {
                api_fail('当前密码不正确', 403);
            }
            if (!preg_match('/^[A-Za-z0-9_.\-\x{4e00}-\x{9fa5}]{2,32}$/u', $newUser)) {
                api_fail('用户名需为 2-32 位字母、数字、下划线、点、短横线或汉字');
            }
            if ($newUser === effective_user()) {
                api_fail('新用户名与当前用户名相同');
            }
            if (!settings_write(array('user' => $newUser))) {
                api_fail('用户名保存失败，请检查目录权限');
            }
            // 用户名已变更：立即退出登录并清除原有登录临时数据
            destroy_auth_session(true);
            json_out(array('ok' => true, 'user' => $newUser, 'logout' => true));
            break;

        case 'backup': {
            // 手动备份：文件名.格式-时间戳.bak，保存在原文件所在目录
            $abs = resolve_path((string) param('path', ''));
            if (!is_file($abs)) {
                api_fail('不是文件');
            }
            $dir = dirname($abs);
            if (!is_writable($dir)) {
                api_fail('该目录没有写入权限', 403);
            }
            $stamp = date('Ymd-His');
            $name = basename($abs) . '-' . $stamp . '.bak';
            $target = unique_path($dir, $name);
            $content = param('content', null);
            $encRaw = trim((string) param('encoding', 'auto'));
            $withBom = ((string) param('bom', '0') === '1') || $encRaw === 'utf-8bom' || $encRaw === 'utf8bom';
            $enc = normalize_encoding($encRaw);
            if ($content !== null) {
                $err = '';
                $bytes = encode_for_disk((string) $content, $enc, $withBom, $err);
                if ($bytes === false) {
                    api_fail($err);
                }
                $ok = @file_put_contents($target, $bytes, LOCK_EX) !== false;
            } else {
                $ok = @copy($abs, $target);
            }
            if (!$ok) {
                @unlink($target);
                api_fail('备份失败，请检查目录权限');
            }
            @chmod($target, 0644);
            json_out(array(
                'ok'   => true,
                'name' => basename($target),
                'path' => rel_path($target),
                'size' => (int) @filesize($target),
            ));
            break;
        }

        case 'chmod': {
            $modeStr = trim((string) param('mode', ''));
            if (!preg_match('/^0?[0-7]{3}$/', $modeStr)) {
                api_fail('权限值需为 3 位八进制数字，例如 644');
            }
            $mode = octdec(ltrim($modeStr, '0') === '' ? '0' : ltrim($modeStr, '0')) & 0777;
            $recursive = (bool) param('recursive', false);
            $paths = param('paths', null);
            if ($paths === null) {
                $paths = array((string) param('path', ''));
            }
            $paths = is_array($paths) ? $paths : array();
            $done = array();
            $failed = array();
            foreach ($paths as $one) {
                try {
                    $abs = resolve_path((string) $one);
                    if (rel_path($abs) === '') {
                        $failed[] = basename($abs) . '（不能修改根目录）';
                        continue;
                    }
                    if (!@chmod($abs, $mode)) {
                        $failed[] = basename($abs) . '（修改失败，可能没有权限）';
                        continue;
                    }
                    if ($recursive && is_dir($abs)) {
                        $stack = array($abs);
                        while ($stack) {
                            $cur = array_pop($stack);
                            $items = @scandir($cur);
                            if (!is_array($items)) {
                                continue;
                            }
                            foreach ($items as $it) {
                                if ($it === '.' || $it === '..') {
                                    continue;
                                }
                                $child = $cur . '/' . $it;
                                @chmod($child, $mode);
                                if (is_dir($child) && !is_link($child)) {
                                    $stack[] = $child;
                                }
                            }
                        }
                    }
                    $done[] = basename($abs);
                } catch (ApiException $e) {
                    $failed[] = basename((string) $one) . '（' . $e->getMessage() . '）';
                }
            }
            if (count($done) === 0 && count($failed) > 0) {
                api_fail(implode('、', $failed));
            }
            json_out(array('ok' => true, 'done' => $done, 'failed' => $failed, 'mode' => decoct($mode)));
            break;
        }

        case 'env':
            json_out(array('ok' => true, 'rows' => env_report()));
            break;

        default:
            api_fail('未知操作', 404);
    }
}

function parse_repo($input) 
{
    $input = trim($input);
    if ($input === '') {
        api_fail('请输入仓库地址');
    }
    if (preg_match('~^(?:https?://)?(?:www\.)?(?:github\.com|git@github\.com)[/:]+([^/]+)/([^/?#]+)~i', $input, $m)) {
        $owner = $m[1];
        $name = preg_replace('/\.git$/i', '', $m[2]);
    } elseif (preg_match('#^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$#', $input, $m)) {
        $owner = $m[1];
        $name = preg_replace('/\.git$/i', '', $m[2]);
    } else {
        api_fail('仓库格式应为 owner/repo 或完整 GitHub 链接');
    }
    if ($owner === '' || $name === '') {
        api_fail('仓库地址不完整');
    }
    $token = trim((string) setting('gh_token', ''));
    return array('owner' => $owner, 'name' => $name, 'token' => $token);
}

function gh_cut($text,  $limit) 
{
    if ($limit <= 0) {
        return $text;
    }
    $len = function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);
    if ($len <= $limit) {
        return $text;
    }
    $cut = function_exists('mb_substr') ? mb_substr($text, 0, $limit, 'UTF-8') : substr($text, 0, $limit);
    return rtrim($cut) . '…';
}

/* 把 README / 发行说明的 Markdown 压成可读纯文本，避免前端渲染风险 */
function gh_strip_md($text) 
{
    if ($text === '') {
        return '';
    }
    $text = str_replace(array("\r\n", "\r"), "\n", $text);
    $text = preg_replace('/```[\s\S]*?```/u', "\n", $text);
    $text = preg_replace('/~~~[\s\S]*?~~~/u', "\n", $text);
    $text = preg_replace('/<!--[\s\S]*?-->/u', ' ', $text);
    $text = preg_replace('/\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)/u', ' ', $text);
    $text = preg_replace('/!\[[^\]]*\]\([^)]*\)/u', ' ', $text);
    $text = preg_replace('/\[([^\]]*)\]\([^)]*\)/u', '$1', $text);
    $text = preg_replace('/<[^>]+>/u', ' ', $text);
    $text = preg_replace('/^\s{0,3}#{1,6}\s*/mu', '', $text);
    $text = preg_replace('/^\s*[>\-\*\+]\s+/mu', '', $text);
    $text = preg_replace('/^\s*\d+\.\s+/mu', '', $text);
    $text = preg_replace('/[*_`~]/u', '', $text);
    $text = preg_replace('/\|/u', ' ', $text);
    $text = preg_replace('/[ \t]+/u', ' ', $text);
    $text = preg_replace('/\n{2,}/u', "\n", $text);
    $text = trim($text);
    if ($text === '') {
        return '';
    }
    // 去掉纯符号/分隔线残留
    $text = preg_replace('/^[\s\-=_]{0,}$/mu', '', $text);
    return trim($text);
}

function gh_readme_summary($md,  $limit = 300) 
{
    $plain = gh_strip_md($md);
    if ($plain === '') {
        return '';
    }
    $lines = preg_split('/\n/u', $plain);
    $buf = '';
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '') {
            if ($buf !== '') {
                break;
            }
            continue;
        }
        $len = function_exists('mb_strlen') ? mb_strlen($line, 'UTF-8') : strlen($line);
        if ($buf === '' && $len < 10) {
            continue; // 跳过标题、导航、徽章残留等短行
        }
        $buf .= ($buf === '' ? '' : ' ') . $line;
        $bufLen = function_exists('mb_strlen') ? mb_strlen($buf, 'UTF-8') : strlen($buf);
        if ($bufLen >= $limit) {
            break;
        }
    }
    if ($buf === '') {
        $buf = $plain;
    }
    return gh_cut($buf, $limit);
}

function github_api($path,  $token,  $accept = 'application/vnd.github+json') 
{
    $headers = array(
        'Accept: ' . $accept,
        'X-GitHub-Api-Version: 2022-11-28',
        'User-Agent: EuPHPFileManager/' . XIAZZI_VERSION,
    );
    if ($token !== '') {
        $headers[] = 'Authorization: token ' . $token;
    }
    $res = http_request('https://api.github.com/' . ltrim($path, '/'), array('timeout' => 40, 'headers' => $headers, 'max_bytes' => 8 * 1024 * 1024));
    if (!$res['ok']) {
        $msg = 'HTTP ' . $res['code'];
        $body = json_decode((string) $res['body'], true);
        if (is_array($body) && isset($body['message'])) {
            $msg = (string) $body['message'];
        }
        if ((int) $res['code'] === 404) {
            $msg = '仓库不存在或为私有仓库';
        } elseif ((int) $res['code'] === 403) {
            $msg = '接口频率超限，请稍后再试或在设置中填写 Token';
        }
        return array('ok' => false, 'error' => $msg, 'body' => (string) $res['body'], 'code' => (int) $res['code']);
    }
    return $res;
}

function settings_public() 
{
    return array(
        'lang'        => (string) setting('lang', 'zh-CN'),
        'theme'       => (string) setting('theme', 'system'),
        'show_hidden' => (bool) setting('show_hidden', false),
        'show_perms'  => (bool) setting('show_perms', false),
        'hide_self'   => (bool) setting('hide_self', true),
        'editor'      => (string) setting('editor', 'normal'),
        'gh_extract'  => (bool) setting('gh_extract', false),
        'link_style'  => link_style(),
        'link_sample_file' => direct_url('example.zip'),
        'link_sample_dir'  => dir_url('example'),
        'script_name' => isset($_SERVER['SCRIPT_NAME']) ? basename((string) $_SERVER['SCRIPT_NAME']) : 'index.php',
        'has_token'   => trim((string) setting('gh_token', '')) !== '',
        'user'        => effective_user(),
        'setup_required' => setup_required(),
        'settings_writable' => @is_writable(XIAZZI_FILE),
        'store'             => 'inline',
    );
}

function boot_data() 
{
    global $CONFIG;
    return array(
        'title'      => (string) $CONFIG['title'],
        'version'    => XIAZZI_VERSION,
        'csrf'       => isset($_SESSION['csrf']) ? (string) $_SESSION['csrf'] : '',
        'auth'       => auth_enabled(),
        'user'       => effective_user(),
        'lang'       => (string) setting('lang', 'zh-CN'),
        'maxUpload'  => (int) $CONFIG['max_upload_mb'],
        'rootName'   => basename(root_dir()),
        'editExt'    => array_values($CONFIG['edit_ext']),
        'storage'    => storage_info(),
        'server'     => 'PHP ' . PHP_VERSION,
        'settings'   => settings_public(),
        'setup'      => setup_required(),
        'php'        => PHP_VERSION,
        'year'       => (int) date('Y'),
    );
}

/* ------------------------------ 首次使用引导页 ------------------------------ */

/* 首次部署时展示的引导页：三步完成管理员账号与密码设置。
 * 独立于主应用渲染，未登录即可访问；程序没有默认密码，
 * 因此只设置新账号与新密码，不再要求输入旧密码。 */
function render_setup_page($title)
{
    $lang = current_lang();
    $dict = i18n_dict();
    if (!isset($dict[$lang])) {
        $lang = 'zh-CN';
    }
    $user0 = effective_user();
    if ($user0 === '') {
        $user0 = 'admin';
    }
    $csrf = isset($_SESSION['csrf']) ? (string) $_SESSION['csrf'] : '';
    $csrfJson = function_exists('json_encode') ? json_encode($csrf) : '""';
    $escTitle = htmlspecialchars((string) $title, ENT_QUOTES, 'UTF-8');
    ?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f1f4f9" media="(prefers-color-scheme:light)">
<meta name="theme-color" content="#070a11" media="(prefers-color-scheme:dark)">
<meta name="robots" content="noindex,nofollow">
<title><?php echo e_t('setup_badge'); ?> · <?php echo $escTitle; ?></title>
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{color-scheme:light dark}
html,body{min-height:100%;margin:0}
body{position:relative;display:flex;align-items:flex-start;justify-content:center;
  padding:calc(22px + env(safe-area-inset-top,0px)) 14px calc(22px + env(safe-area-inset-bottom,0px));
  background:#070a11;color:#eef2f9;overflow-x:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Segoe UI","Microsoft YaHei",sans-serif}
body::before{content:"";position:fixed;inset:-25%;z-index:0;pointer-events:none;background:
  radial-gradient(circle at 22% 14%, rgba(91,108,255,.40), transparent 46%),
  radial-gradient(circle at 80% 86%, rgba(20,184,166,.26), transparent 44%),
  radial-gradient(circle at 62% 32%, rgba(139,92,246,.24), transparent 40%);
  filter:blur(36px);animation:drift 20s ease-in-out infinite alternate}
@keyframes drift{from{transform:scale(1) translate3d(0,0,0)}to{transform:scale(1.1) translate3d(2%,-2%,0)}}
.wrap{position:relative;z-index:1;width:100%;max-width:432px;margin:auto}
.card{background:rgba(17,22,34,.78);border:1px solid rgba(255,255,255,.10);border-radius:26px;
  padding:22px 22px 15px;box-shadow:0 30px 80px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.06);
  -webkit-backdrop-filter:blur(24px);backdrop-filter:blur(24px)}
.brand{display:flex;align-items:center;gap:11px;min-width:0}
.mark{flex:0 0 auto;width:44px;height:44px;border-radius:14px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(140deg,#6d7cff,#8b5cf6 55%,#22d3ee);box-shadow:0 10px 24px rgba(91,108,255,.42)}
.mark svg{width:24px;height:24px;stroke:#fff;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.bt{flex:1;min-width:0}
.bt b{display:block;font-size:14px;font-weight:650;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bt span{display:block;margin-top:2px;font-size:11px;color:#8b97ac}
.badge{flex:0 0 auto;font-size:10px;letter-spacing:.4px;color:#bcc6ff;background:rgba(109,124,255,.18);
  border:1px solid rgba(109,124,255,.35);border-radius:999px;padding:4px 9px;white-space:nowrap}
.steps{display:flex;align-items:center;gap:5px;margin:18px 0 18px}
.st{display:flex;align-items:center;gap:5px;flex:0 0 auto}
.st i{width:21px;height:21px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-style:normal;font-size:10.5px;font-weight:700;color:#8b97ac;background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.12);transition:.25s}
.st em{font-style:normal;font-size:10.5px;color:#7d8aa0;transition:.25s;white-space:nowrap}
.st.on i{background:linear-gradient(135deg,#6d7cff,#8b5cf6);border-color:transparent;color:#fff;
  box-shadow:0 4px 12px rgba(91,108,255,.45)}
.st.on em{color:#dfe4ff;font-weight:600}
.st.done i{background:rgba(109,124,255,.18);border-color:rgba(109,124,255,.35);color:#aab6ff}
.bar{flex:1 1 auto;height:2px;border-radius:2px;background:rgba(255,255,255,.09);overflow:hidden;min-width:8px}
.bar i{display:block;height:100%;width:0;border-radius:2px;background:linear-gradient(90deg,#6d7cff,#8b5cf6);transition:width .35s ease}
.pane{display:none}
.pane.on{display:block;animation:panein .26s ease both}
@keyframes panein{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
h1,h2{margin:0 0 6px;font-weight:680;letter-spacing:.2px}
h1{font-size:20px;line-height:1.32}
h2{font-size:18px;line-height:1.35}
.lead{margin:0 0 16px;font-size:12.5px;line-height:1.65;color:#93a0b6}
.points{list-style:none;margin:0 0 18px;padding:0;display:flex;flex-direction:column;gap:9px}
.points li{display:flex;align-items:flex-start;gap:10px;padding:10px 11px;border-radius:13px;
  background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.065)}
.pi{flex:0 0 auto;width:29px;height:29px;border-radius:9px;display:flex;align-items:center;justify-content:center;
  background:rgba(109,124,255,.16);color:#a9b4ff}
.pi svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.pt{min-width:0}
.pt b{display:block;font-size:12.5px;font-weight:600;line-height:1.5}
.pt small{display:block;margin-top:2px;font-size:11px;line-height:1.55;color:#8794a9}
.btn{width:100%;height:50px;border:0;border-radius:15px;font-size:14.5px;font-weight:650;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:transform .12s,opacity .2s}
.btn:active{transform:scale(.99)}
.btn svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.primary{color:#fff;background:linear-gradient(135deg,#6d7cff,#8b5cf6);box-shadow:0 12px 26px rgba(91,108,255,.36)}
.primary[disabled]{opacity:.6;cursor:default;box-shadow:none}
.ghost{color:#c3ccdd;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.13);box-shadow:none}
.link{display:block;margin:14px auto 2px;padding:6px;text-align:center;font-size:11.5px;color:#8f9bb4;text-decoration:none}
.link:active{color:#c7d2e5}
.field{margin-bottom:12px}
.field>label{display:block;margin:0 2px 6px;font-size:11.5px;color:#93a0b6;letter-spacing:.2px}
.inp{position:relative}
.inp input{width:100%;height:48px;border-radius:13px;border:1px solid rgba(255,255,255,.12);
  background:rgba(255,255,255,.045);color:#eef2f9;padding:0 46px 0 14px;font-size:16px;outline:none;
  transition:border-color .18s,box-shadow .18s,background .18s;-webkit-appearance:none}
.inp input::placeholder{color:#5f6c82;font-size:13px}
.inp input:focus{border-color:rgba(109,124,255,.85);box-shadow:0 0 0 4px rgba(109,124,255,.16);background:rgba(255,255,255,.07)}
.inp input.bad{border-color:rgba(240,68,56,.7);box-shadow:0 0 0 4px rgba(240,68,56,.12)}
.eye{position:absolute;right:4px;top:4px;width:40px;height:40px;border:0;border-radius:10px;background:none;
  color:#8e9ab0;cursor:pointer;display:flex;align-items:center;justify-content:center}
.eye:active{background:rgba(255,255,255,.08)}
.eye svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.hint{margin:6px 2px 0;font-size:10.8px;line-height:1.55;color:#77849a}
.meter{display:flex;align-items:center;gap:4px;margin-top:8px}
.meter i{flex:1 1 0;height:4px;border-radius:2px;background:rgba(255,255,255,.10);transition:background .2s}
.meter span{flex:0 0 auto;min-width:36px;text-align:right;font-size:10.5px;color:#8b97ac}
.meter.m1 i:nth-child(1){background:#f04438}
.meter.m2 i:nth-child(-n+2){background:#f79009}
.meter.m3 i:nth-child(-n+3){background:#5b9dff}
.meter.m4 i{background:#12b76a}
.meter.m1 span{color:#ff8593}.meter.m2 span{color:#ffc06a}.meter.m3 span{color:#8fbaff}.meter.m4 span{color:#57d99b}
.rules{list-style:none;display:flex;flex-wrap:wrap;gap:5px 12px;margin:9px 2px 0;padding:0}
.rules li{position:relative;padding-left:13px;font-size:10.6px;line-height:1.6;color:#77849a;transition:color .2s}
.rules li::before{content:"";position:absolute;left:0;top:6px;width:6px;height:6px;border-radius:50%;
  background:rgba(255,255,255,.22);transition:background .2s}
.rules li.ok{color:#8fe3b6}
.rules li.ok::before{background:#12b76a}
.err{min-height:17px;margin:9px 2px 0;font-size:11.8px;line-height:1.5;color:#ff8593}
.acts{display:flex;gap:8px;margin-top:4px}
.acts .ghost{flex:0 0 38%;height:48px;font-size:13px}
.acts .primary{flex:1 1 auto;height:48px;font-size:14px}
.note{margin:11px 2px 0;font-size:10.4px;line-height:1.6;color:#5f6c80;text-align:center}
.done{display:flex;justify-content:center;padding:10px 0 8px}
.tick{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  background:rgba(18,183,106,.14);color:#34d399;box-shadow:0 0 0 8px rgba(18,183,106,.06);animation:pop .42s cubic-bezier(.2,1.4,.4,1) both}
.tick svg{width:30px;height:30px;stroke:currentColor;fill:none;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
@keyframes pop{from{transform:scale(.6);opacity:0}to{transform:scale(1);opacity:1}}
.account{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:14px 0 12px;padding:12px 14px;
  border-radius:13px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);font-size:11.5px;color:#8b97ac}
.account b{font-size:13px;color:#eef2f9;font-weight:650;word-break:break-all;text-align:right}
.dots{display:flex;justify-content:center;gap:5px;margin:0 0 16px}
.dots i{width:6px;height:6px;border-radius:50%;background:#6d7cff;opacity:.35;animation:blink 1.2s infinite}
.dots i:nth-child(2){animation-delay:.18s}.dots i:nth-child(3){animation-delay:.36s}
@keyframes blink{0%,100%{opacity:.25;transform:scale(.85)}50%{opacity:1;transform:scale(1)}}
.foot{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:16px;padding-top:11px;
  border-top:1px solid rgba(255,255,255,.07);font-size:10.2px;color:#5d6a80}
@media (max-width:420px){
  body{padding:calc(14px + env(safe-area-inset-top,0px)) 10px calc(14px + env(safe-area-inset-bottom,0px))}
  .card{padding:19px 16px 13px;border-radius:22px}
  h1{font-size:18.5px}
  .points li{padding:9px 10px}
  .st em{display:none}
  .acts .ghost{flex:0 0 34%}
}
@media (max-width:340px){.badge{display:none}.acts{flex-direction:column}.acts .ghost,.acts .primary{flex:1 1 auto;width:100%}}
/* 引导页背景与配色跟随手机系统（浅色 / 深色） */
@media (prefers-color-scheme:light){
  body{background:#f1f4f9;color:#1f2328}
  body::before{background:
    radial-gradient(circle at 22% 14%, rgba(91,108,255,.30), transparent 46%),
    radial-gradient(circle at 80% 86%, rgba(20,184,166,.20), transparent 44%),
    radial-gradient(circle at 62% 32%, rgba(139,92,246,.18), transparent 40%)}
  .card{background:rgba(255,255,255,.88);border-color:rgba(15,23,42,.10);
    box-shadow:0 24px 60px rgba(15,23,42,.16),inset 0 1px 0 rgba(255,255,255,.92)}
  .bt span{color:#65718a}
  .badge{color:#4048bd;background:rgba(109,124,255,.12);border-color:rgba(109,124,255,.30)}
  .st i{color:#6f7a8e;background:rgba(15,23,42,.045);border-color:rgba(15,23,42,.12)}
  .st em{color:#6b7688}
  .st.on em{color:#3a41b8}
  .st.done i{background:rgba(109,124,255,.12);border-color:rgba(109,124,255,.30);color:#5158cc}
  .bar{background:rgba(15,23,42,.09)}
  .lead{color:#5a6577}
  .points li{background:rgba(15,23,42,.035);border-color:rgba(15,23,42,.08)}
  .pi{background:rgba(109,124,255,.13);color:#525ad0}
  .pt small{color:#65718a}
  .ghost{color:#3d4759;background:rgba(15,23,42,.04);border-color:rgba(15,23,42,.14)}
  .link{color:#5f6c82}
  .link:active{color:#232f42}
  .field>label{color:#5a6577}
  .inp input{background:#fff;border-color:rgba(15,23,42,.14);color:#1f2328}
  .inp input::placeholder{color:#9aa4b3}
  .inp input:focus{background:#fff}
  .eye{color:#78849a}
  .eye:active{background:rgba(15,23,42,.06)}
  .hint{color:#65718a}
  .meter i{background:rgba(15,23,42,.10)}
  .meter span{color:#6f7a8e}
  .meter.m1 span{color:#d92d20}.meter.m2 span{color:#b45309}.meter.m3 span{color:#1d4ed8}.meter.m4 span{color:#0f8a53}
  .rules li{color:#65718a}
  .rules li::before{background:rgba(15,23,42,.24)}
  .rules li.ok{color:#0f8a53}
  .err{color:#d92d20}
  .account{background:rgba(15,23,42,.04);border-color:rgba(15,23,42,.09);color:#65718a}
  .account b{color:#1f2328}
  .note{color:#65718a}
  .foot{border-top-color:rgba(15,23,42,.09);color:#6b7688}
  .tick{background:rgba(18,183,106,.12);color:#0f8a53;box-shadow:0 0 0 8px rgba(18,183,106,.05)}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<main class="wrap">
  <section class="card" aria-labelledby="sgH1">
    <header class="brand">
      <div class="mark"><svg viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.1c.6 0 1.2.3 1.6.8l1 1.2h6.3A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-12A2.5 2.5 0 0 1 3 16.5v-9Z"/></svg></div>
      <div class="bt"><b><?php echo $escTitle; ?></b><span><?php echo e_t('setup_badge'); ?> · Setup</span></div>
      <span class="badge"><?php echo e_t('setup_badge'); ?></span>
    </header>

    <nav class="steps" id="sgSteps" aria-label="<?php echo e_t('setup_badge'); ?>">
      <div class="st on" data-step="1"><i>1</i><em><?php echo e_t('setup_step1'); ?></em></div>
      <div class="bar"><i data-bar="1"></i></div>
      <div class="st" data-step="2"><i>2</i><em><?php echo e_t('setup_step2'); ?></em></div>
      <div class="bar"><i data-bar="2"></i></div>
      <div class="st" data-step="3"><i>3</i><em><?php echo e_t('setup_step3'); ?></em></div>
    </nav>

    <div class="panes">
      <section class="pane on" data-pane="1">
        <h1 id="sgH1"><?php echo e_t('setup_hello'); ?></h1>
        <p class="lead"><?php echo e_t('setup_lead'); ?></p>
        <ul class="points">
          <li>
            <span class="pi"><svg viewBox="0 0 24 24"><path d="M12 3.5 19 6v6c0 4.2-2.9 7.4-7 8.5-4.1-1.1-7-4.3-7-8.5V6l7-2.5Z"/><path d="m9 12 2 2 4-4"/></svg></span>
            <span class="pt"><b><?php echo e_t('setup_p1'); ?></b><small><?php echo e_t('setup_p1_hint'); ?></small></span>
          </li>
          <li>
            <span class="pi"><svg viewBox="0 0 24 24"><path d="M12 12v3M4 12a8 8 0 1 0 16 0 8 8 0 0 0-16 0Z"/></svg></span>
            <span class="pt"><b><?php echo e_t('setup_p2'); ?></b><small><?php echo e_t('setup_sub'); ?></small></span>
          </li>
          <li>
            <span class="pi"><svg viewBox="0 0 24 24"><rect x="4.5" y="10" width="15" height="10" rx="2.5"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/></svg></span>
            <span class="pt"><b><?php echo e_t('setup_p3'); ?></b><small><?php echo e_t('setup_note'); ?></small></span>
          </li>
        </ul>
        <button type="button" class="btn primary" id="sgStart"><?php echo e_t('setup_start'); ?>
          <svg viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg></button>
      </section>

      <section class="pane" data-pane="2">
        <h2><?php echo e_t('setup_title'); ?></h2>
        <p class="lead"><?php echo e_t('setup_sub'); ?></p>
        <form id="sgForm" novalidate autocomplete="on">
          <div class="field">
            <label for="sgUser"><?php echo e_t('setup_user_label'); ?></label>
            <div class="inp">
              <input id="sgUser" name="user" type="text" value="<?php echo htmlspecialchars($user0, ENT_QUOTES, 'UTF-8'); ?>"
                placeholder="<?php echo e_t('setup_user_ph'); ?>" autocomplete="username" spellcheck="false" autocapitalize="off">
            </div>
          </div>
          <div class="field">
            <label for="sgPass"><?php echo e_t('setup_new_label'); ?></label>
            <div class="inp">
              <input id="sgPass" name="pass" type="password" placeholder="<?php echo e_t('setup_new_ph'); ?>" autocomplete="new-password">
              <button type="button" class="eye" data-eye="sgPass" aria-label="<?php echo e_t('setup_show_pass'); ?>">
                <svg viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/></svg>
              </button>
            </div>
            <div class="meter" id="sgMeter" data-lv="0" aria-hidden="true"><i></i><i></i><i></i><i></i><span id="sgLv"><?php echo e_t('setup_strength'); ?></span></div>
          </div>
          <div class="field">
            <label for="sgPass2"><?php echo e_t('setup_new2_label'); ?></label>
            <div class="inp">
              <input id="sgPass2" name="pass2" type="password" placeholder="<?php echo e_t('setup_new2_ph'); ?>" autocomplete="new-password">
              <button type="button" class="eye" data-eye="sgPass2" aria-label="<?php echo e_t('setup_show_pass'); ?>">
                <svg viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/></svg>
              </button>
            </div>
          </div>
          <ul class="rules" id="sgRules">
            <li data-rule="len"><?php echo e_t('setup_rule_len'); ?></li>
            <li data-rule="mix"><?php echo e_t('setup_rule_mix'); ?></li>
            <li data-rule="same"><?php echo e_t('setup_rule_same'); ?></li>
            <li data-rule="weak"><?php echo e_t('setup_rule_weak'); ?></li>
          </ul>
          <p class="err" id="sgErr" role="alert" aria-live="polite"></p>
          <div class="acts">
            <button type="button" class="btn ghost" id="sgPrev"><?php echo e_t('setup_prev'); ?></button>
            <button type="submit" class="btn primary" id="sgGo"><?php echo e_t('setup_create'); ?></button>
          </div>
          <p class="note"><?php echo e_t('setup_note'); ?></p>
        </form>
      </section>

      <section class="pane" data-pane="3">
        <div class="done"><span class="tick"><svg viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7"/></svg></span></div>
        <h2><?php echo e_t('setup_ok'); ?></h2>
        <p class="lead" id="sgOkSub"><?php echo e_t('setup_ok_sub'); ?></p>
        <div class="account"><span><?php echo e_t('setup_ok_user'); ?></span><b id="sgOkUser">—</b></div>
        <p class="note" id="sgOkNote"><?php echo e_t('setup_ok_note'); ?></p>
        <div class="dots" aria-hidden="true"><i></i><i></i><i></i></div>
        <button type="button" class="btn primary" id="sgEnter"><?php echo e_t('setup_enter'); ?></button>
      </section>
    </div>

    <footer class="foot">
      <span>PHP <?php echo PHP_VERSION; ?> · <?php echo XIAZZI_VERSION; ?></span>
      <span><?php echo e_t('setup_badge'); ?></span>
    </footer>
  </section>
</main>
<script>
(function ()  {
  var CSRF = <?php echo $csrfJson; ?>;
  var TXT = {
    lv1: <?php echo json_encode(t('setup_lv1')); ?>,
    lv2: <?php echo json_encode(t('setup_lv2')); ?>,
    lv3: <?php echo json_encode(t('setup_lv3')); ?>,
    lv4: <?php echo json_encode(t('setup_lv4')); ?>,
    errUser: <?php echo json_encode(t('setup_err_user')); ?>,
    errPass: <?php echo json_encode(t('setup_err_pass')); ?>,
    errWeak: <?php echo json_encode(t('setup_err_weak')); ?>,
    errPass2: <?php echo json_encode(t('setup_err_pass2')); ?>,
    errSame: <?php echo json_encode(t('setup_err_same')); ?>,
    errNet: <?php echo json_encode(t('setup_net')); ?>,
    saving: <?php echo json_encode(t('setup_saving')); ?>,
    create: <?php echo json_encode(t('setup_create')); ?>
  };
  var WEAK = ['admin123', 'admin888', '12345678', '123456789', '11111111', 'password', 'password1', 'qwerty123', 'abc123456', 'adminadmin'];

  var steps = document.querySelectorAll('#sgSteps .st');
  var bars = document.querySelectorAll('#sgSteps .bar i');
  var panes = document.querySelectorAll('.pane');
  var err = document.getElementById('sgErr');
  var go = document.getElementById('sgGo');
  var form = document.getElementById('sgForm');
  var userEl = document.getElementById('sgUser');
  var passEl = document.getElementById('sgPass');
  var pass2El = document.getElementById('sgPass2');
  var meter = document.getElementById('sgMeter');
  var lvEl = document.getElementById('sgLv');
  var done = false;

  function setStep(n)  {
    var i;
    for (i = 0; i < panes.length; i++)  {
      panes[i].classList.toggle('on', Number(panes[i].getAttribute('data-pane')) === n);
    }
    for (i = 0; i < steps.length; i++)  {
      var num = Number(steps[i].getAttribute('data-step'));
      steps[i].classList.toggle('on', num === n);
      steps[i].classList.toggle('done', num < n);
    }
    for (i = 0; i < bars.length; i++)  {
      bars[i].style.width = Number(bars[i].getAttribute('data-bar')) < n ? '100%' : '0%';
    }
    err.textContent = '';
    try  { window.scrollTo(0, 0); } catch (e)  {}
  }

  function score(p)  {
    var s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[A-Za-z]/.test(p) && /[0-9]/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 4);
  }

  function paint()  {
    var p = passEl.value || '';
    var u = (userEl.value || '').trim();
    var sc = p ? score(p) : 0;
    meter.className = 'meter' + (sc ? ' m' + sc : '');
    var names = ['', TXT.lv1, TXT.lv2, TXT.lv3, TXT.lv4];
    lvEl.textContent = sc ? names[sc] : '';
    var ok = {
      len: p.length >= 8,
      mix: /[A-Za-z]/.test(p) && /[0-9]/.test(p),
      same: p !== '' && u !== '' && p.toLowerCase() !== u.toLowerCase(),
      weak: p !== '' && WEAK.indexOf(p.toLowerCase()) < 0
    };
    var list = document.querySelectorAll('#sgRules li');
    for (var i = 0; i < list.length; i++)  {
      var k = list[i].getAttribute('data-rule');
      list[i].classList.toggle('ok', !!ok[k]);
    }
  }

  function fail(msg, node)  {
    err.textContent = msg;
    if (node)  {
      node.classList.add('bad');
      try  { node.focus(); } catch (e)  {}
      setTimeout(function ()  { node.classList.remove('bad'); }, 1600);
    }
  }

  var eyes = document.querySelectorAll('.eye');
  for (var e = 0; e < eyes.length; e++)  {
    eyes[e].addEventListener('click', function ()  {
      var id = this.getAttribute('data-eye');
      var input = document.getElementById(id);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      this.setAttribute('aria-label', input.type === 'password' ? this.getAttribute('aria-label') : this.getAttribute('aria-label'));
    });
  }

  document.getElementById('sgStart').addEventListener('click', function ()  {
    setStep(2);
    setTimeout(function ()  { try  { passEl.focus(); } catch (e)  {} }, 120);
  });
  document.getElementById('sgPrev').addEventListener('click', function ()  { setStep(1); });

  userEl.addEventListener('input', paint);
  passEl.addEventListener('input', paint);
  pass2El.addEventListener('input', paint);

  form.addEventListener('submit', function (ev)  {
    ev.preventDefault();
    if (done) return;
    err.textContent = '';
    var user = (userEl.value || '').trim();
    var p1 = passEl.value || '';
    var p2 = pass2El.value || '';

    if (!user)  { fail(TXT.errUser, userEl); return; }
    if (p1.length < 8 || !/[A-Za-z]/.test(p1) || !/[0-9]/.test(p1))  { fail(TXT.errPass, passEl); return; }
    if (WEAK.indexOf(p1.toLowerCase()) >= 0)  { fail(TXT.errWeak, passEl); return; }
    if (p1.toLowerCase() === user.toLowerCase())  { fail(TXT.errSame, passEl); return; }
    if (p1 !== p2)  { fail(TXT.errPass2, pass2El); return; }

    go.disabled = true;
    go.textContent = TXT.saving;

    fetch('?api=setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify({ user: user, pass: p1, pass2: p2, remember: '1' })
    }).then(function (r)  {
      return r.json().catch(function ()  { throw new Error(TXT.errNet); });
    }).then(function (res)  {
      if (!res || !res.ok)  { throw new Error((res && res.error) || TXT.errNet); }
      done = true;
      passEl.value = '';
      pass2El.value = '';
      document.getElementById('sgOkUser').textContent = res.user || user;
      setStep(3);
      setTimeout(goHome, 1400);
    }).catch(function (ex)  {
      go.disabled = false;
      go.textContent = TXT.create;
      fail(ex.message || TXT.errNet, null);
    });
  });

  function goHome()  {
    var url = location.pathname;
    location.replace(url);
  }
  document.getElementById('sgEnter').addEventListener('click', goHome);
  paint();
})();
</script>
</body>
</html>
    <?php
    exit;
}


/* ------------------------------ 入口 ------------------------------ */

if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$API = isset($_GET['api']) ? (string) $_GET['api'] : '';

// 直链（兼容模式）：?dl=签名
if ($API === '' && isset($_GET['dl'])) {
    try {
        serve_file(parse_link((string) $_GET['dl']), !isset($_GET['download']));
    } catch (ApiException $e) {
        link_error_page($e);
    }
}

// 直链（简洁模式）：{本文件.php}/{相对路径}，不带任何查询参数
// 文件夹直链：{站点}/{文件夹}/ 或 {本文件.php}/{文件夹}/，打开对应目录
if ($API === '' && !isset($_GET['dl'])) {
    $PRETTY_DIR = pretty_dir_path();
    if ($PRETTY_DIR !== '') {
        header('Location: ' . base_url() . '?p=' . rawurlencode($PRETTY_DIR), true, 302);
        exit;
    }
    $PRETTY_REL = pretty_path();
    if ($PRETTY_REL !== '') {
        $PRETTY_ABS = resolve_path($PRETTY_REL);
        if (is_dir($PRETTY_ABS)) {
            $PRETTY_DIR = rel_path($PRETTY_ABS);
            header('Location: ' . base_url() . '?p=' . rawurlencode($PRETTY_DIR), true, 302);
            exit;
        }
        try {
            serve_file($PRETTY_REL, !isset($_GET['download']));
        } catch (ApiException $e) {
            link_error_page($e);
        }
    }
}

try {
    if ($API !== '') {
        handle_api($API);
    }
} catch (ApiException $e) {
    json_out(array('ok' => false, 'error' => localize_error($e->getMessage()), 'code' => $e->getCode()), $e->getCode() >= 400 ? $e->getCode() : 400);
} catch (Exception $e) {
    json_out(array('ok' => false, 'error' => localize_error('服务器内部错误') . '：' . $e->getMessage()), 500);
}

$LOGGED_IN = is_logged_in();
$BOOT = boot_data();
$BOOT_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
    $BOOT_FLAGS |= JSON_INVALID_UTF8_SUBSTITUTE;
}
$BOOT_JSON = xz_json_encode($BOOT, $BOOT_FLAGS);
if ($BOOT_JSON === false) {
    $BOOT_JSON = '{}';
}
$I18N_JSON = xz_json_encode(i18n_dict(), $BOOT_FLAGS);
if ($I18N_JSON === false) {
    $I18N_JSON = '{}';
}
$HTML_TITLE = htmlspecialchars((string) $CONFIG['title'], ENT_QUOTES, 'UTF-8');

/* 首次使用：尚未设置密码时，任何入口都先走引导页；
 * 程序没有默认密码，设置完成后才会进入登录页。 */
if (!$LOGGED_IN && setup_required()) {
    render_setup_page((string) $CONFIG['title']);
}

if (!$LOGGED_IN) {
    $loginLang = (string) setting('lang', 'zh-CN');
    $loginDict = i18n_dict();
    if (!isset($loginDict[$loginLang])) {
        $loginLang = 'zh-CN';
    }
    ?>
<!DOCTYPE html>
<html lang="<?php echo $loginLang; ?>" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#080b12">
<title><?php echo t('login'); ?> · <?php echo $HTML_TITLE; ?></title>
<link rel="stylesheet" href="data:text/css,">
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;padding:24px;background:#070a11;color:#eef2f9;
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Segoe UI","Microsoft YaHei",sans-serif;overflow:hidden}
body::before{content:"";position:fixed;inset:-25%;background:
  radial-gradient(circle at 25% 18%, rgba(91,108,255,.42), transparent 48%),
  radial-gradient(circle at 78% 82%, rgba(20,184,166,.30), transparent 46%),
  radial-gradient(circle at 60% 30%, rgba(139,92,246,.24), transparent 40%);
  filter:blur(34px);z-index:0;animation:drift 18s ease-in-out infinite alternate}
@keyframes drift{from{transform:scale(1) translate3d(0,0,0)}to{transform:scale(1.12) translate3d(2%,-2%,0)}}
.card{position:relative;z-index:1;width:100%;max-width:392px;background:rgba(17,22,34,.76);
  border:1px solid rgba(255,255,255,.10);border-radius:28px;padding:34px 26px 22px;
  box-shadow:0 30px 80px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.06);
  -webkit-backdrop-filter:blur(24px);backdrop-filter:blur(24px)}
.logo{width:58px;height:58px;border-radius:19px;background:linear-gradient(140deg,#6d7cff,#8b5cf6 55%,#22d3ee);
  display:flex;align-items:center;justify-content:center;box-shadow:0 12px 30px rgba(91,108,255,.45)}
h1{font-size:23px;margin:16px 0 5px;letter-spacing:.2px;font-weight:650}
.sub{margin:0 0 26px;font-size:13px;color:#93a0b6}
label{display:block;font-size:12px;color:#93a0b6;margin:0 0 8px;letter-spacing:.2px}
.field{position:relative;margin-bottom:14px}
.field input{width:100%;height:52px;border-radius:15px;border:1px solid rgba(255,255,255,.12);
  background:rgba(255,255,255,.045);color:#eef2f9;padding:0 46px 0 16px;font-size:15px;outline:none;transition:.18s}
.field input:focus{border-color:rgba(109,124,255,.85);box-shadow:0 0 0 4px rgba(109,124,255,.17);background:rgba(255,255,255,.07)}
.field .eye{position:absolute;right:6px;top:6px;width:40px;height:40px;border:0;background:none;cursor:pointer;
  display:flex;align-items:center;justify-content:center;color:#8e9ab0;border-radius:11px}
.field .eye:active{background:rgba(255,255,255,.08)}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:2px 0 4px}
.check{display:flex;align-items:center;gap:8px;font-size:12.5px;color:#a9b5c8;cursor:pointer;user-select:none;margin:0}
.check input{width:17px;height:17px;accent-color:#6d7cff;margin:0}
.langs{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.langs button{border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.04);color:#a9b5c8;
  font-size:11.5px;padding:6px 10px;border-radius:9px;cursor:pointer;transition:.16s}
.langs button.on{background:rgba(109,124,255,.22);border-color:rgba(109,124,255,.6);color:#dfe4ff}
button.submit{width:100%;height:54px;margin-top:20px;border:0;border-radius:16px;cursor:pointer;
  background:linear-gradient(135deg,#6d7cff,#8b5cf6);color:#fff;font-size:15.5px;font-weight:600;
  box-shadow:0 14px 30px rgba(91,108,255,.38);transition:transform .12s,box-shadow .2s}
button.submit:active{transform:scale(.985);box-shadow:0 8px 18px rgba(91,108,255,.3)}
button.submit[disabled]{opacity:.65;cursor:default}
.err{min-height:20px;margin-top:12px;font-size:12.5px;color:#ff8593;text-align:center}
.foot{margin-top:20px;padding-top:16px;border-top:1px solid rgba(255,255,255,.07);
  display:flex;align-items:center;justify-content:space-between;font-size:11px;color:#5d6a80}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#34d399;margin-right:5px;box-shadow:0 0 8px #34d399}
@media (max-width:420px){body{padding:16px}.card{padding:28px 20px 18px;border-radius:24px}}
</style>
</head>
<body>
<form class="card" id="loginForm" autocomplete="on">
  <div class="logo">
    <svg width="31" height="31" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.1c.6 0 1.2.3 1.6.8l1 1.2h6.3A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-12A2.5 2.5 0 0 1 3 16.5v-9Z"/>
    </svg>
  </div>
  <h1><?php echo $HTML_TITLE; ?></h1>
  <p class="sub"><?php echo htmlspecialchars(t('brand_sub'), ENT_QUOTES, 'UTF-8'); ?></p>
  <label for="user"><?php echo htmlspecialchars(t('user'), ENT_QUOTES, 'UTF-8'); ?></label>
  <div class="field">
    <input id="user" name="user" type="text" autocomplete="username" placeholder="<?php echo htmlspecialchars(t('user_ph'), ENT_QUOTES, 'UTF-8'); ?>" value="<?php echo htmlspecialchars(effective_user(), ENT_QUOTES, 'UTF-8'); ?>">
  </div>
  <label for="pass"><?php echo htmlspecialchars(t('pass'), ENT_QUOTES, 'UTF-8'); ?></label>
  <div class="field">
    <input id="pass" name="pass" type="password" autocomplete="current-password" placeholder="<?php echo htmlspecialchars(t('pass_ph'), ENT_QUOTES, 'UTF-8'); ?>" autofocus>
    <button class="eye" type="button" id="eye" aria-label="toggle">
      <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="2.6"/></svg>
    </button>
  </div>
  <div class="row">
    <label class="check"><input type="checkbox" id="remember" checked><?php echo htmlspecialchars(t('remember'), ENT_QUOTES, 'UTF-8'); ?></label>
    <div class="langs" id="langs">
      <button type="button" data-lang="zh-CN" class="<?php echo $loginLang === 'zh-CN' ? 'on' : ''; ?>">简</button>
      <button type="button" data-lang="zh-TW" class="<?php echo $loginLang === 'zh-TW' ? 'on' : ''; ?>">繁</button>
      <button type="button" data-lang="en" class="<?php echo $loginLang === 'en' ? 'on' : ''; ?>">EN</button>
      <button type="button" data-lang="ja" class="<?php echo $loginLang === 'ja' ? 'on' : ''; ?>">日</button>
      <button type="button" data-lang="ko" class="<?php echo $loginLang === 'ko' ? 'on' : ''; ?>">한</button>
      <button type="button" data-lang="es" class="<?php echo $loginLang === 'es' ? 'on' : ''; ?>">ES</button>
    </div>
  </div>
  <button class="submit" type="submit" id="go"><?php echo htmlspecialchars(t('enter'), ENT_QUOTES, 'UTF-8'); ?></button>
  <div class="err" id="err"></div>
  <div class="foot">
    <span><i class="dot"></i><?php echo htmlspecialchars(t('version'), ENT_QUOTES, 'UTF-8'); ?> <?php echo XIAZZI_VERSION; ?> · PHP <?php echo PHP_VERSION; ?></span>
    <span><?php echo htmlspecialchars($BOOT['rootName'], ENT_QUOTES, 'UTF-8'); ?></span>
  </div>
</form>
<script>
(function ()  {
  var form = document.getElementById('loginForm');
  var input = document.getElementById('pass');
  var userInput = document.getElementById('user');
  var err = document.getElementById('err');
  var go = document.getElementById('go');
  var remember = document.getElementById('remember');
  var eye = document.getElementById('eye');
  eye.addEventListener('click', function ()  {
    input.type = input.type === 'password' ? 'text' : 'password';
    input.focus();
  });
  Array.prototype.forEach.call(document.querySelectorAll('#langs button'), function (btn)  {
    btn.addEventListener('click', function ()  {
      document.cookie = 'xiazzi_lang=' + btn.getAttribute('data-lang') + ';path=/;max-age=31536000;SameSite=Lax';
      location.reload();
    });
  });
  form.addEventListener('submit', function (event)  {
    event.preventDefault();
    err.textContent = '';
    go.disabled = true;
    fetch('?api=login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Lang': document.documentElement.lang },
      body: JSON.stringify({ user: userInput.value, pass: input.value, remember: remember.checked ? '1' : '0' })
    }).then(function (r)  { return r.json(); }).then(function (res)  {
      if (res && res.ok) { location.reload(); return; }
      err.textContent = (res && res.error) || <?php echo json_encode(t('bad_login'), JSON_UNESCAPED_UNICODE); ?>;
      go.disabled = false;
      input.select();
    }).catch(function ()  {
      err.textContent = <?php echo json_encode(t('err_net'), JSON_UNESCAPED_UNICODE); ?>;
      go.disabled = false;
    });
  });
})();
</script>
</body>
</html>
    <?php
    exit;
}
?>
<!DOCTYPE html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1">
<meta name="theme-color" content="#ffffff">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="format-detection" content="telephone=no">
<title><?php echo $HTML_TITLE; ?> · 文件管理</title>
<meta name="description" content="易优PHP文件管理器：PHP 单文件文件管理器，适配手机与电脑，支持 zip / tar.gz、在线编辑与 GitHub 下载">
<style>
/* ============================================================
   0. 变量与基础
   ============================================================ */
:root{
  --bg:#eceff5; --app:#ffffff; --surface:#ffffff; --surface-2:#f5f7fb; --surface-3:#eaeef6;
  --text:#0e1319; --text-2:#5b6577; --text-3:#96a0b2;
  --line:rgba(15,19,25,.07); --line-2:rgba(15,19,25,.12);
  --accent:#5b6cff; --accent-2:#8b5cf6; --accent-soft:rgba(var(--accent-rgb),.10);
  --accent-rgb:91,108,255;
  --grad-brand:linear-gradient(140deg,#6d7cff,#8b5cf6 60%,#22d3ee);
  --grad-hero:linear-gradient(135deg,#5b6cff 0%,#7c5cf7 52%,#a855f7 100%);
  --grad-btn:linear-gradient(135deg,#6d7cff,#8b5cf6);
  --grad-fab:linear-gradient(140deg,#6d7cff,#8b5cf6);
  --hero-shadow:0 14px 34px rgba(var(--accent-rgb),.30);
  --accent-shadow:0 8px 18px rgba(var(--accent-rgb),.30);
  --accent-shadow-2:0 12px 26px rgba(var(--accent-rgb),.42);
  --brand-shadow:0 8px 22px rgba(var(--accent-rgb),.35);
  --ico-r:11px; --chip-r:11px; --fab-r:18px; --row-h:62px; --hero-r:var(--r-xl);
  --danger:#f04438; --danger-soft:rgba(240,68,56,.10);
  --ok:#12b76a; --warn:#f79009;
  --shadow-1:0 1px 2px rgba(16,24,40,.04),0 8px 24px rgba(16,24,40,.06);
  --shadow-2:0 20px 60px rgba(16,24,40,.20);
  --shadow-3:0 12px 32px rgba(16,24,40,.12);
  --r-xl:26px; --r-lg:20px; --r-md:14px; --r-sm:10px;
  --safe-b:env(safe-area-inset-bottom,0px); --safe-t:env(safe-area-inset-top,0px);
  --ease:cubic-bezier(.22,.68,.35,1);
  --sidebar:264px;
  --tb-h:58px;
}
[data-theme="dark"]{
  --bg:#05070c; --app:#0b1019; --surface:#111826; --surface-2:#0d1420; --surface-3:#182234;
  --text:#eaeef7; --text-2:#95a1b6; --text-3:#66738a;
  --line:rgba(255,255,255,.07); --line-2:rgba(255,255,255,.13);
  --accent:#7d8bff; --accent-2:#a78bfa; --accent-soft:rgba(125,139,255,.15);
  --danger:#ff6b74; --danger-soft:rgba(255,107,116,.14);
  --ok:#34d399; --warn:#fbbf24;
  --shadow-1:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
  --shadow-2:0 24px 70px rgba(0,0,0,.6);
  --shadow-3:0 16px 40px rgba(0,0,0,.45);
}

*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{height:100%;margin:0;overscroll-behavior:none}
body{
  background:var(--bg);color:var(--text);overflow:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","HarmonyOS Sans SC","Segoe UI","Microsoft YaHei",sans-serif;
  font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
}
button{font-family:inherit;color:inherit;border:0;background:none;padding:0;cursor:pointer;font-size:inherit}
input,textarea,select{font-family:inherit;font-size:inherit;color:inherit}
img{display:block;max-width:100%}
::selection{background:rgba(var(--accent-rgb),.22)}
.sprite{position:absolute;width:0;height:0;overflow:hidden}
.ic{width:20px;height:20px;flex:0 0 auto;display:block;stroke:currentColor;fill:none;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}
.ic-sm{width:17px;height:17px}
.ic-lg{width:24px;height:24px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}

/* ============================================================
   1. 骨架
   ============================================================ */
.app{display:flex;height:100dvh;height:100vh;background:var(--bg);overflow:hidden}
.main{position:relative;flex:1;min-width:0;display:flex;flex-direction:column;background:var(--bg)}

/* ---------- 桌面侧栏 ---------- */
.sidebar{display:none;flex-direction:column;width:var(--sidebar);flex:0 0 var(--sidebar);
  background:var(--app);border-right:1px solid var(--line);padding:20px 16px 18px;gap:6px}
.brand{display:flex;align-items:center;gap:12px;padding:4px 8px 18px}
.brand-mark{width:42px;height:42px;border-radius:14px;display:flex;align-items:center;justify-content:center;
  background:var(--grad-brand);color:#fff;
  box-shadow:var(--brand-shadow)}
.brand h1{font-size:16.5px;margin:0;font-weight:680;letter-spacing:.2px}
.brand p{margin:1px 0 0;font-size:11.5px;color:var(--text-3)}
.nav-label{font-size:11px;color:var(--text-3);padding:14px 10px 6px;letter-spacing:.6px;text-transform:uppercase}
.nav-item{display:flex;align-items:center;gap:11px;height:42px;padding:0 11px;border-radius:12px;
  color:var(--text-2);font-size:13.5px;transition:background .16s,color .16s;text-align:left}
.nav-item:hover{background:var(--surface-2);color:var(--text)}
.nav-item.active{background:var(--accent-soft);color:var(--accent);font-weight:600}
.side-storage{margin-top:auto;background:var(--surface-2);border:1px solid var(--line);border-radius:16px;padding:14px}
.ss-top{display:flex;align-items:baseline;justify-content:space-between;font-size:12px;color:var(--text-2)}
.ss-top b{font-size:13px;color:var(--text)}
.ss-bar{height:6px;border-radius:6px;background:var(--surface-3);margin:10px 0 8px;overflow:hidden}
.ss-bar i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .5s var(--ease)}
.ss-foot{display:flex;justify-content:space-between;font-size:11px;color:var(--text-3)}
.side-foot{display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--text-3);padding:14px 8px 2px;margin-top:auto}
.linkbtn{color:var(--accent);font-size:11.5px}
.linkbtn:hover{text-decoration:underline}

/* ---------- 顶栏 ---------- */
.topbar{position:relative;z-index:20;flex:0 0 auto;display:flex;align-items:center;gap:8px;
  height:calc(var(--tb-h) + var(--safe-t));padding:var(--safe-t) 10px 0 6px;
  background:var(--bg);border-bottom:1px solid transparent;transition:border-color .2s,background .2s}
.topbar.scrolled{background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:saturate(160%) blur(16px);border-bottom-color:var(--line)}
.tb-lead{display:flex;align-items:center;gap:2px;flex:0 0 auto}
.tb-tx{min-width:0;flex:1;display:flex;flex-direction:column;justify-content:center;padding:0 2px}
.tb-title{font-size:17px;font-weight:660;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.25}
.tb-sub{font-size:11.5px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.3}
.tb-tools{display:flex;align-items:center;gap:2px;flex:0 0 auto}
.iconbtn{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;color:var(--text-2);transition:background .15s,color .15s,transform .1s}
.iconbtn:hover{background:var(--surface-3);color:var(--text)}
.iconbtn:active{transform:scale(.94)}
.iconbtn.on{background:var(--accent-soft);color:var(--accent)}
.iconbtn[hidden]{display:none}

/* 搜索层 */
.searchbar{position:absolute;inset:var(--safe-t) 0 0 0;display:none;align-items:center;gap:8px;padding:0 12px 0 8px;background:var(--bg);z-index:5}
.searchbar.on{display:flex}
.searchbar .field{flex:1;display:flex;align-items:center;gap:8px;height:40px;background:var(--surface-3);border-radius:12px;padding:0 10px;color:var(--text-3)}
.searchbar input{flex:1;min-width:0;border:0;background:none;outline:none;font-size:14.5px;color:var(--text);height:100%}
.searchbar input::-webkit-search-cancel-button{display:none}

/* ---------- 滚动区 ---------- */
.scroll{flex:1;overflow-y:auto;overflow-x:hidden;-webkit-overflow-scrolling:touch;
  padding:6px 12px calc(156px + var(--safe-b));
  scroll-padding-bottom:calc(140px + var(--safe-b));scroll-behavior:smooth}
/* 复制/剪切条出现时再让出它的高度，避免压住最后一行 */
.scroll.clip-on{padding-bottom:calc(212px + var(--safe-b));
  scroll-padding-bottom:calc(196px + var(--safe-b))}
.scroll::-webkit-scrollbar{width:8px;height:8px}
.scroll::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:8px}
.scroll::-webkit-scrollbar-track{background:transparent}
.inner{max-width:1080px;margin:0 auto}

/* ---------- 存储卡 ---------- */
.hero{position:relative;overflow:hidden;border-radius:var(--r-xl);padding:18px 18px 16px;margin:4px 0 14px;
  background:var(--grad-hero);color:#fff;
  box-shadow:var(--hero-shadow);border-radius:var(--hero-r)}
.hero::after{content:"";position:absolute;right:-40px;top:-56px;width:180px;height:180px;border-radius:50%;
  background:radial-gradient(circle,rgba(255,255,255,.30),transparent 66%)}
.hero::before{content:"";position:absolute;left:-30px;bottom:-70px;width:160px;height:160px;border-radius:50%;
  background:radial-gradient(circle,rgba(255,255,255,.16),transparent 68%)}
.hero-top{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.hero-label{font-size:12px;opacity:.82;letter-spacing:.3px}
.hero-value{font-size:25px;font-weight:700;letter-spacing:.2px;line-height:1.2;margin-top:2px;font-variant-numeric:tabular-nums}
.hero-value small{font-size:11.5px;font-weight:500;opacity:.8;margin-left:5px}
.hero-btn{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 13px;border-radius:11px;
  background:rgba(255,255,255,.20);color:#fff;font-size:12.5px;font-weight:600;backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,.22)}
.hero-btn:active{transform:scale(.97)}
.hero-bar{position:relative;height:7px;border-radius:7px;background:rgba(255,255,255,.24);margin:14px 0 9px;overflow:hidden}
.hero-bar i{display:block;height:100%;border-radius:7px;background:#fff;transition:width .6s var(--ease)}
.hero-foot{position:relative;display:flex;justify-content:space-between;font-size:11.5px;opacity:.86;font-variant-numeric:tabular-nums}

/* ---------- 设置内存储卡 ---------- */
.setstore[hidden]{display:none}
.setstore{position:relative;overflow:hidden;border-radius:20px;padding:16px 16px 13px;margin:2px 0 16px;
  background:var(--grad-hero);color:#fff;box-shadow:var(--hero-shadow)}
.setstore::after{content:"";position:absolute;right:-40px;top:-58px;width:170px;height:170px;border-radius:50%;pointer-events:none;
  background:radial-gradient(circle,rgba(255,255,255,.30),transparent 66%)}
.setstore::before{content:"";position:absolute;left:-34px;bottom:-74px;width:150px;height:150px;border-radius:50%;pointer-events:none;
  background:radial-gradient(circle,rgba(255,255,255,.15),transparent 68%)}
.setstore-top{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.setstore-label{font-size:11.5px;opacity:.84;letter-spacing:.3px}
.setstore-value{font-size:24px;font-weight:700;line-height:1.2;margin-top:3px;letter-spacing:.2px;font-variant-numeric:tabular-nums}
.setstore-value small{font-size:11px;font-weight:500;opacity:.82;margin-left:4px}
.setstore-top>div{min-width:0}
.setstore-bar{position:relative;height:7px;border-radius:7px;background:rgba(255,255,255,.24);margin:14px 0 9px;overflow:hidden}
.setstore-bar i{display:block;height:100%;border-radius:7px;background:#fff;transition:width .6s var(--ease)}
.setstore-foot{position:relative;display:flex;justify-content:space-between;gap:8px;font-size:11px;opacity:.88;
  font-variant-numeric:tabular-nums;flex-wrap:wrap}
.setstore-path{position:relative;display:flex;align-items:center;gap:5px;margin-top:10px;font-size:10.5px;opacity:.74;
  min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.setstore-path .ic{flex:0 0 auto;opacity:.85}
.setstore-path b{font-weight:500;overflow:hidden;text-overflow:ellipsis}

/* ---------- 分类胶囊 ---------- */
.chips{display:flex;gap:7px;overflow-x:auto;padding:2px 0 12px;scrollbar-width:none;-ms-overflow-style:none}
.chips::-webkit-scrollbar{display:none}
.chip{flex:0 0 auto;height:33px;padding:0 13px;border-radius:var(--chip-r);background:var(--surface);border:1px solid var(--line);
  color:var(--text-2);font-size:12.5px;display:inline-flex;align-items:center;gap:6px;transition:.16s;white-space:nowrap}
.chip .ic{opacity:.7}
.chip.on{background:var(--accent);border-color:transparent;color:#fff;box-shadow:var(--accent-shadow)}
.chip.on .ic{opacity:1}

/* ---------- 列表头 ---------- */
.listhead{display:flex;align-items:center;justify-content:space-between;gap:6px 10px;padding:2px 2px 9px;flex-wrap:wrap}
/* 列表头只保留“当前文件夹统计”，不再有“目录名 · N”计数标题；统计条整体左对齐 */
.lh-left{display:flex;align-items:center;justify-content:flex-start;gap:0;min-width:0;flex:0 1 auto;flex-wrap:wrap}
.lh-right{display:flex;align-items:center;gap:6px;flex:0 0 auto;margin-left:auto}
/* 当前文件夹统计：文件数 · 文件夹数 · 总大小（含子文件夹） */
.lh-stats{display:inline-flex;align-items:center;flex-wrap:wrap;min-width:0;max-width:100%;
  font-size:11px;line-height:1.45;color:var(--text-3);font-variant-numeric:tabular-nums;letter-spacing:.1px}
.lh-stats[hidden]{display:none}
.lh-stats .st{display:inline-flex;align-items:center;gap:3px;white-space:nowrap}
.lh-stats .st + .st{position:relative;margin-left:7px;padding-left:8px}
.lh-stats .st + .st::before{content:"";position:absolute;left:0;top:50%;width:1px;height:9px;margin-top:-4.5px;
  border-radius:1px;background:var(--line-2)}
.lh-stats .ic{width:12px;height:12px;flex:0 0 auto;opacity:.7}
.lh-stats b{font-weight:650;color:var(--text-2)}
.lh-stats .st-load{color:var(--text-3);opacity:.75}
@media (max-width:520px){
  .lh-stats .ic{display:none}
  .lh-stats .st + .st{margin-left:6px;padding-left:7px}
  .listhead{gap:4px 8px}
  .listhead .lh-left{flex:1 1 auto}
  .lh-right{gap:5px}
}
.seg{display:flex;background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:2px;gap:2px}
.seg button{width:30px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--text-3)}
.seg button.on{background:var(--surface-3);color:var(--text)}
.sortbtn{display:inline-flex;align-items:center;gap:5px;height:30px;padding:0 9px;border-radius:9px;
  background:var(--surface);border:1px solid var(--line);color:var(--text-2);font-size:12px}

/* ---------- 表格头（桌面） ---------- */
.thead{display:none;align-items:center;gap:10px;padding:0 12px;height:34px;color:var(--text-3);font-size:11.5px;letter-spacing:.3px}
.thead .th-name{flex:1;display:flex;align-items:center;gap:4px;padding-left:4px}
.thead button{display:inline-flex;align-items:center;gap:3px;color:inherit;font-size:inherit;padding:4px 1px}
.thead button.on{color:var(--text)}
.thead .th-size{width:88px;text-align:right;justify-content:flex-end}
.thead .th-time{width:132px}
.thead .th-perm{width:132px}
.thead .th-act{width:40px}

/* ---------- 列表 ---------- */
.list{display:flex;flex-direction:column;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);
  overflow:hidden;box-shadow:var(--shadow-1)}
.row{position:relative;display:grid;grid-template-columns:34px minmax(0,1fr) 34px;align-items:center;gap:8px;
  padding:0 10px 0 8px;height:var(--row-h);transition:background .14s;user-select:none;-webkit-user-select:none;
  border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.row:hover{background:var(--surface-2)}
.row:active{background:var(--surface-3)}
.row.selected{background:var(--accent-soft)}
.row.selected:hover{background:rgba(var(--accent-rgb),.16)}
.r-lead{position:relative;width:34px;height:34px;display:flex;align-items:center;justify-content:center;flex:0 0 auto}
.r-ico{width:34px;height:34px;border-radius:var(--ico-r);display:flex;align-items:center;justify-content:center;
  background:var(--surface-3);color:var(--text-2)}
.r-ico .ic{width:19px;height:19px}
.k-folder{background:var(--accent-soft);color:var(--accent)}
.k-image{background:rgba(16,185,129,.13);color:#0ea371}
.k-video{background:rgba(244,114,182,.14);color:#db2777}
.k-audio{background:rgba(245,158,11,.15);color:#d97706}
.k-doc{background:rgba(59,130,246,.13);color:#2563eb}
.k-archive{background:rgba(139,92,246,.14);color:#7c3aed}
.k-text{background:rgba(14,165,233,.13);color:#0284c7}
[data-theme="dark"] .k-folder{color:#93a1ff}
[data-theme="dark"] .k-image{color:#34d399}
[data-theme="dark"] .k-video{color:#f9a8d4}
[data-theme="dark"] .k-audio{color:#fbbf24}
[data-theme="dark"] .k-doc{color:#93c5fd}
[data-theme="dark"] .k-archive{color:#c4b5fd}
[data-theme="dark"] .k-text{color:#7dd3fc}
.r-check{position:absolute;inset:0;display:none;align-items:center;justify-content:center}
.r-check i{width:20px;height:20px;border-radius:50%;border:1.8px solid var(--line-2);background:var(--surface);transition:.15s}
.row.selected .r-check i{background:var(--accent);border-color:var(--accent)}
.row.selected .r-check i::after{content:"";display:block;width:5px;height:9px;border:2px solid #fff;border-top:0;border-left:0;
  transform:rotate(40deg) translate(4px,1px);border-radius:1px}
.list.selecting .r-ico{display:none}
.list.selecting .r-check{display:flex}
.r-main{min-width:0;display:flex;flex-direction:column;gap:1px}
.r-name{font-size:14px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.1px}
.r-name mark{background:rgba(245,158,11,.28);color:inherit;border-radius:3px;padding:0 1px}
.r-meta{font-size:11px;color:var(--text-3);display:flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden}
.r-meta .dot{width:2.5px;height:2.5px;border-radius:50%;background:currentColor;opacity:.55}
.r-col{display:none;font-size:12px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.r-size{text-align:right}
.r-perm code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;background:var(--surface-3);
  padding:1px 5px;border-radius:5px;color:var(--text-2)}
.r-act{width:32px;height:32px;border-radius:9px;display:flex;align-items:center;justify-content:center;color:var(--text-3)}
.r-act:hover{background:var(--surface-3);color:var(--text)}
.r-col.r-time{display:none}

/* 空状态 / 骨架 */
.empty{display:none;flex-direction:column;align-items:center;justify-content:center;padding:56px 20px;text-align:center;color:var(--text-3)}
.empty.on{display:flex}
.empty .eico{width:74px;height:74px;border-radius:24px;background:var(--surface);border:1px solid var(--line);
  display:flex;align-items:center;justify-content:center;color:var(--text-3);margin-bottom:14px;box-shadow:var(--shadow-1)}
.empty h3{margin:0 0 6px;font-size:15px;color:var(--text);font-weight:600}
.empty p{margin:0;font-size:12.5px;max-width:260px;line-height:1.6}
.skel{height:62px;display:flex;align-items:center;gap:12px;padding:0 12px;border-bottom:1px solid var(--line)}
.skel i{display:block;border-radius:8px;background:linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2));
  background-size:200% 100%;animation:sh 1.3s infinite}
@keyframes sh{0%{background-position:200% 0}100%{background-position:-200% 0}}

/* ---------- 底部标签栏（移动端） ---------- */
.tabbar{position:absolute;left:0;right:0;bottom:0;z-index:30;display:flex;
  padding:6px 6px calc(6px + var(--safe-b));background:color-mix(in srgb,var(--app) 92%,transparent);
  backdrop-filter:saturate(180%) blur(20px);border-top:1px solid var(--line)}
.tab{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;padding:5px 0 3px;border-radius:12px;
  color:var(--text-3);font-size:10.5px;font-weight:500;transition:color .16s}
.tab.on{color:var(--accent)}
.tab .ic{width:22px;height:22px}
.tab:active{background:var(--surface-2)}
.tab .dotmark{position:absolute;margin:-2px 0 0 16px;width:5px;height:5px;border-radius:50%;background:var(--danger)}

/* ---------- 悬浮按钮 ---------- */
.fab{position:absolute;right:14px;bottom:calc(78px + var(--safe-b));z-index:31;width:52px;height:52px;border-radius:var(--fab-r);
  display:flex;align-items:center;justify-content:center;color:#fff;
  background:var(--grad-fab);box-shadow:var(--accent-shadow-2);
  transition:transform .18s var(--ease),box-shadow .2s,opacity .18s}
.fab .ic{width:23px;height:23px}
.fab:active{transform:scale(.94)}
/* 列表滚动时收缩淡出，避免浮层压住正在浏览的内容 */
.fab.dim{opacity:.34;transform:scale(.82)}

/* ---------- 选择模式顶栏与操作条 ---------- */
.selbar{display:none;align-items:center;justify-content:space-between;gap:10px;padding:0 12px 8px}
.selbar.on{display:flex}
.selbar .cnt{font-size:13px;font-weight:600}
.selbar .cnt span{color:var(--accent)}
.selbar .acts{display:flex;gap:6px}
.selbar .acts button{font-size:12px;color:var(--accent);padding:5px 8px;border-radius:8px;background:var(--accent-soft)}
.selbar .acts button.plain{background:transparent;color:var(--text-2)}

.selactions{position:fixed;left:0;right:0;bottom:0;z-index:70;display:flex;align-items:center;gap:2px;
  padding:8px 6px calc(8px + var(--safe-b));background:color-mix(in srgb,var(--app) 96%,transparent);
  backdrop-filter:blur(22px);border-top:1px solid var(--line);box-shadow:0 -8px 26px rgba(16,24,40,.10);
  overflow-x:auto;overflow-y:hidden;scrollbar-width:none;-webkit-overflow-scrolling:touch;
  transform:translateY(110%);opacity:0;transition:transform .26s var(--ease),opacity .2s;
  pointer-events:none;visibility:hidden}
.selactions::-webkit-scrollbar{display:none}
.selactions.on{transform:none;opacity:1;pointer-events:auto;visibility:visible}
.selactions button{display:flex;flex-direction:column;align-items:center;gap:3px;font-size:10.5px;color:var(--text-2);
  flex:1 0 auto;min-width:54px;padding:5px 2px;border-radius:10px}
.selactions button .ic{width:21px;height:21px}
.selactions button:active{background:var(--surface-2)}
.selactions button.danger{color:var(--danger)}
.selactions button:disabled{opacity:.35}
.footer-space{display:none}

/* ---------- 剪贴板提示 ---------- */
.clipbar{position:absolute;left:12px;right:12px;bottom:calc(146px + var(--safe-b));z-index:32;display:flex;align-items:center;gap:9px;
  padding:9px 10px 9px 14px;border-radius:15px;background:var(--text);color:var(--app);
  box-shadow:var(--shadow-2);transform:translateY(140%);opacity:0;transition:.24s var(--ease);pointer-events:none}
.clipbar.on{transform:none;opacity:1;pointer-events:auto}
[data-theme="dark"] .clipbar{background:#e9eef8;color:#0b1019}
.clipbar .txt{font-size:12.5px;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.clipbar .txt b{font-weight:600}
.clipbar button{font-size:12px;font-weight:600;padding:6px 10px;border-radius:9px;background:rgba(255,255,255,.16);color:inherit}
[data-theme="dark"] .clipbar button{background:rgba(0,0,0,.08)}
.clipbar .x{width:28px;height:28px;padding:0;display:flex;align-items:center;justify-content:center;background:transparent}

/* ============================================================
   2. 弹层
   ============================================================ */
.backdrop{position:fixed;inset:0;z-index:60;background:rgba(6,9,15,.46);opacity:0;pointer-events:none;transition:opacity .24s;
  backdrop-filter:blur(2px)}
.backdrop.on{opacity:1;pointer-events:auto}
[data-theme="dark"] .backdrop{background:rgba(0,0,0,.62)}

.sheet{position:fixed;left:0;right:0;bottom:0;z-index:78;background:var(--surface);
  border-radius:26px 26px 0 0;box-shadow:0 -12px 50px rgba(0,0,0,.22);
  transform:translateY(102%);transition:transform .28s var(--ease);
  max-height:88dvh;display:flex;flex-direction:column;padding-bottom:var(--safe-b)}
.sheet.on{transform:none}
.sheet-handle{width:38px;height:4px;border-radius:4px;background:var(--line-2);margin:9px auto 4px;flex:0 0 auto}
.sheet-head{display:flex;align-items:center;gap:10px;padding:8px 18px 10px}
.sheet-head .st{min-width:0;flex:1}
.sheet-head strong{display:block;font-size:15px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sheet-head span{display:block;font-size:11.5px;color:var(--text-3);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sheet-body{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:2px 12px 14px;-webkit-overflow-scrolling:touch}

/* ---------- 新建面板（图标磁贴） ---------- */
.creategrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:2px;padding:6px 4px 12px}
.createitem{display:flex;flex-direction:column;align-items:center;gap:9px;padding:10px 2px 9px;border-radius:16px;
  min-width:0;transition:background .16s,transform .12s var(--ease)}
.createitem:active{background:var(--surface-2);transform:scale(.955)}
.cico{width:50px;height:50px;border-radius:15px;display:flex;align-items:center;justify-content:center;color:#fff;flex:0 0 auto;
  box-shadow:0 6px 14px rgba(16,24,40,.16)}
.cico .ic{width:24px;height:24px}
.cico-blue{background:linear-gradient(150deg,#4a9bff,#1f6bff);box-shadow:0 7px 16px rgba(31,107,255,.34)}
.cico-orange{background:linear-gradient(150deg,#ffb03a,#f5871f);box-shadow:0 7px 16px rgba(245,135,31,.32)}
.cico-green{background:linear-gradient(150deg,#25c795,#0aa272);box-shadow:0 7px 16px rgba(10,162,114,.30)}
.cico-dark{background:linear-gradient(150deg,#4b5563,#24292f);box-shadow:0 7px 16px rgba(36,41,47,.32)}
.cico-teal{background:linear-gradient(150deg,#38c6cf,#0d9aa8);box-shadow:0 7px 16px rgba(13,154,168,.30)}
.cico-violet{background:linear-gradient(150deg,#8b7bff,#6254e8);box-shadow:0 7px 16px rgba(98,84,232,.30)}
.cico-gray{background:linear-gradient(150deg,#8a94a3,#5d6673);box-shadow:0 7px 16px rgba(93,102,115,.28)}
.cname{font-size:11.5px;line-height:1.35;color:var(--text-2);text-align:center;min-width:0;max-width:100%;word-break:break-word}
.sheet-foot{flex:0 0 auto;padding:2px 16px 14px}
.sheet-foot .btn{width:100%}
[data-theme="dark"] .cico{box-shadow:0 6px 16px rgba(0,0,0,.40)}

/* ---------- 磁贴菜单（更多 / 已选 / 打开方式） ---------- */
.cico-red{background:linear-gradient(150deg,#ff7a6b,#ef4a3d);box-shadow:0 7px 16px rgba(239,74,61,.32)}
.cico-amber{background:linear-gradient(150deg,#ffca4a,#f0a020);box-shadow:0 7px 16px rgba(240,160,32,.30)}
.cico-indigo{background:linear-gradient(150deg,#7c8cff,#4f5ce8);box-shadow:0 7px 16px rgba(79,92,232,.30)}
.cico-slate{background:linear-gradient(150deg,#6f7b8c,#3f4a58);box-shadow:0 7px 16px rgba(63,74,88,.30)}
.cico-pink{background:linear-gradient(150deg,#ff8fb4,#e8477f);box-shadow:0 7px 16px rgba(232,71,127,.30)}
.creategrid.tilegrid{gap:4px 2px;padding:8px 2px 14px}
.creategrid.tilegrid .createitem.is-danger .cname{color:var(--danger)}
.creategrid.tilegrid .createitem.is-danger .cico{background:linear-gradient(150deg,#ff7a6b,#ef4a3d)}
/* 排序磁贴：选中态 + 角标 */
.sortgrid .createitem{position:relative;padding-bottom:11px}
.sortgrid .createitem.is-on{background:rgba(var(--accent-rgb),.09)}
.sortgrid .createitem.is-on .cname{color:var(--accent);font-weight:650}
.sortgrid .cwrap{display:flex;flex-direction:column;align-items:center;gap:2px;min-width:0;max-width:100%}
.sortgrid .csub{font-size:10px;line-height:1.2;color:var(--text-3);letter-spacing:.2px}
.sortgrid .createitem.is-on .csub{color:var(--accent);opacity:.9}
.sortgrid .cico{position:relative}
.sortgrid .cicheck{position:absolute;right:-4px;top:-4px;width:19px;height:19px;border-radius:50%;
  background:var(--app);color:var(--accent);display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 0 2px var(--app),0 2px 6px rgba(16,24,40,.18)}
.sortgrid .cicheck .ic{width:12px;height:12px}
@media (max-width:360px){.sortgrid .cico{width:46px;height:46px}.sortgrid .cname{font-size:11px}}

/* ---------- 统计 / 按类型 ---------- */
.statgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin:2px 0 12px}
.statcell{background:var(--surface-2);border:1px solid var(--line);border-radius:15px;padding:12px 14px;min-width:0}
.statcell b{display:block;font-size:19px;font-weight:650;letter-spacing:-.2px;color:var(--text);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.statcell span{display:block;font-size:11px;color:var(--text-3);margin-top:3px}
.statsec{background:var(--surface-2);border:1px solid var(--line);border-radius:16px;padding:12px 14px 10px}
.statsec-h{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:4px}
.statsec-h b{font-size:13px;font-weight:600;color:var(--text)}
.statsec-h span{font-size:11px;color:var(--text-3)}
.typerow{display:flex;align-items:center;gap:9px;padding:8px 0;min-width:0}
.typerow + .typerow{border-top:1px solid var(--line)}
.trico{width:26px;height:26px;border-radius:8px;background:var(--surface);border:1px solid var(--line);
  display:flex;align-items:center;justify-content:center;font-size:10.5px;font-weight:700;color:var(--text-2);
  flex:0 0 auto;text-transform:uppercase}
.trname{font-size:12.5px;font-weight:550;color:var(--text);flex:0 0 auto;max-width:34%;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.trbar{flex:1 1 auto;min-width:24px;height:6px;border-radius:6px;background:var(--surface-3);overflow:hidden}
.trbar i{display:block;height:100%;border-radius:6px;background:var(--grad-btn);min-width:4px}
.trnum{font-size:11px;color:var(--text-3);flex:0 0 auto;min-width:36px;text-align:right}
.statempty{font-size:12px;color:var(--text-3);padding:14px 4px;text-align:center}

/* 弹层打开时让出底部选择工具栏，避免遮挡弹层最后一行内容 */
body.sheet-open .selactions{transform:translateY(112%);opacity:0;visibility:hidden;pointer-events:none}
body.sheet-open .clipbar{opacity:0;pointer-events:none}
body.sheet-open .fab{opacity:0;pointer-events:none}

.menu-item{display:flex;align-items:center;gap:13px;width:100%;padding:12px 12px;border-radius:13px;text-align:left;
  font-size:14px;color:var(--text);transition:background .14s}
.menu-item:hover{background:var(--surface-2)}
.menu-item:active{background:var(--surface-3)}
.menu-item .mi{width:34px;height:34px;border-radius:11px;background:var(--surface-2);display:flex;align-items:center;justify-content:center;color:var(--text-2);flex:0 0 auto}
.menu-item .mt{flex:1;min-width:0}
.menu-item .mt small{display:block;font-size:11.5px;color:var(--text-3);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.menu-item.danger{color:var(--danger)}
.menu-item.danger .mi{background:var(--danger-soft);color:var(--danger)}
.menu-item:disabled{opacity:.45}
.menu-title{font-size:11px;color:var(--text-3);padding:10px 12px 4px;letter-spacing:.4px}
.menu-sep{height:1px;background:var(--line);margin:6px 12px}

/* 对话框 */
.dialog{position:fixed;left:50%;top:50%;z-index:88;width:min(400px,calc(100vw - 40px));
  transform:translate(-50%,-46%) scale(.96);opacity:0;pointer-events:none;transition:.22s var(--ease);
  background:var(--surface);border-radius:22px;box-shadow:var(--shadow-2);padding:22px 20px 16px;border:1px solid var(--line)}
.dialog.on{transform:translate(-50%,-50%);opacity:1;pointer-events:auto}
.dialog h3{margin:0 0 6px;font-size:16.5px;font-weight:660}
.dialog p{margin:0 0 14px;font-size:13px;color:var(--text-2);line-height:1.6}
.dialog .field{width:100%;height:46px;border-radius:13px;border:1px solid var(--line-2);background:var(--surface-2);
  padding:0 14px;outline:none;font-size:14.5px;transition:.16s}
.dialog .field:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft);background:var(--surface)}
.dialog .hint{font-size:11.5px;color:var(--danger);min-height:16px;margin-top:7px}
.dialog-actions{display:flex;gap:9px;margin-top:14px}

/* ---------- 压缩对话框（卡片式） ---------- */
.cmpdlg{position:fixed;inset:0;z-index:86;display:flex;align-items:center;justify-content:center;
  padding:22px 18px calc(22px + var(--safe-b));opacity:0;pointer-events:none;transition:opacity .2s var(--ease)}
.cmpdlg.on{opacity:1;pointer-events:auto}
.cmpcard{width:min(418px,100%);max-height:calc(100dvh - 44px);display:flex;flex-direction:column;
  background:var(--surface);border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow-2);
  transform:translateY(10px) scale(.975);opacity:0;transition:transform .26s var(--ease),opacity .22s;overflow:hidden}
.cmpdlg.on .cmpcard{transform:none;opacity:1}
.cmphead{flex:0 0 auto;padding:22px 22px 2px}
.cmphead h3{margin:0;font-size:17px;font-weight:650;letter-spacing:-.2px;color:var(--text)}
.cmphead p{margin:6px 0 0;font-size:11.5px;color:var(--text-3);line-height:1.5;
  display:flex;align-items:center;gap:6px;min-width:0}
.cmphead p .ic{width:12px;height:12px;flex:0 0 auto;opacity:.85}
.cmphead p span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cmpbody{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:18px 22px 2px}
.cmpfield{display:block;margin:0 0 20px}
.cmplabel{display:block;font-size:11.5px;color:var(--text-3);letter-spacing:.2px;margin-bottom:3px}
.cmpinput{width:100%;height:38px;border:0;border-bottom:1px solid var(--line-2);background:transparent;
  font-size:15px;color:var(--text);padding:0;outline:none;border-radius:0;transition:border-color .16s}
.cmpinput:focus{border-bottom-color:var(--accent)}
.cmpinput::placeholder{color:var(--text-3)}
.cmprow{display:flex;gap:20px}
.cmprow .cmpfield{flex:1 1 0;min-width:0}
.cmpsel{position:relative;display:flex;align-items:center;min-width:0}
.cmpsel select{-webkit-appearance:none;appearance:none;width:100%;height:38px;border:0;border-radius:0;
  border-bottom:1px solid var(--line-2);background:transparent;font-size:14.5px;color:var(--text);
  padding:0 22px 0 0;outline:none;cursor:pointer;font-family:inherit}
.cmpsel select:focus{border-bottom-color:var(--accent)}
.cmpsel .ic{position:absolute;right:1px;width:13px;height:13px;color:var(--text-3);pointer-events:none}
[data-theme="dark"] .cmpsel select option{background:#111826;color:#eaeef7}
.cmpcheck{display:flex;align-items:center;gap:10px;padding:2px 0 4px;cursor:pointer;user-select:none;
  -webkit-tap-highlight-color:transparent}
.cmpbox{width:19px;height:19px;border-radius:6px;border:1.5px solid var(--line-2);display:flex;
  align-items:center;justify-content:center;flex:0 0 auto;color:transparent;transition:.16s}
.cmpbox .ic{width:12px;height:12px}
.cmpcheck.on .cmpbox{background:var(--accent);border-color:var(--accent);color:#fff}
.cmpcheck.on .cmptext{color:var(--text)}
.cmptext{font-size:13px;color:var(--text-2);line-height:1.45;min-width:0}
.cmpfoot{flex:0 0 auto;display:flex;justify-content:flex-end;align-items:center;gap:2px;padding:12px 12px 10px}
.cmpbtn{height:40px;min-width:64px;padding:0 15px;border-radius:11px;font-size:14px;font-weight:600;
  color:var(--text-2);transition:background .16s,color .16s,transform .12s}
.cmpbtn:active{background:var(--surface-2);transform:scale(.97)}
.cmpbtn.primary{color:var(--accent)}
.cmpbtn.primary:disabled{opacity:.42;pointer-events:none}
@media (max-width:420px){
  .cmpdlg{padding:16px 12px calc(16px + var(--safe-b))}
  .cmpcard{border-radius:20px;max-height:calc(100dvh - 32px)}
  .cmphead{padding:20px 18px 0}
  .cmphead h3{font-size:16.5px}
  .cmpbody{padding:16px 18px 0}
  .cmprow{gap:16px}
  .cmpfoot{padding:10px 8px 8px}
}
@media (max-height:520px){
  .cmpdlg{padding:10px 12px}
  .cmphead{padding:16px 18px 0}
  .cmpbody{padding-top:12px}
}
.btn{flex:1;height:45px;border-radius:13px;font-size:14px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:6px;transition:.15s}
.btn-ghost{background:var(--surface-2);color:var(--text-2)}
.btn-ghost:hover{background:var(--surface-3)}
.btn-primary{background:var(--grad-btn);color:#fff;box-shadow:var(--accent-shadow)}
.btn-primary:active{transform:scale(.98)}
.btn-danger{background:var(--danger);color:#fff;box-shadow:0 8px 18px rgba(240,68,56,.28)}
.btn[disabled]{opacity:.5}

/* 单选 / 分段控件 */
.segmented{display:flex;gap:4px;background:var(--surface-2);padding:3px;border-radius:12px}
.segmented button{flex:1;height:34px;border-radius:9px;font-size:12.5px;color:var(--text-2);font-weight:500;transition:.16s;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:0}
.segmented button .ic{width:14px;height:14px;flex:0 0 auto}
.segmented button.on{background:var(--surface);color:var(--text);box-shadow:0 1px 3px rgba(16,24,40,.12);font-weight:600}
.langgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px;background:var(--surface-2);padding:4px;border-radius:12px}
.langgrid button{height:34px;min-width:0;border:0;border-radius:9px;background:transparent;color:var(--text-2);
  font-size:12px;font-weight:500;font-family:inherit;cursor:pointer;transition:.16s;padding:0 4px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.langgrid button.on{background:var(--surface);color:var(--text);box-shadow:0 1px 3px rgba(16,24,40,.12);font-weight:600}

/* 开关 */
.switch{position:relative;width:44px;height:26px;border-radius:26px;background:var(--surface-3);transition:.2s;flex:0 0 auto;border:1px solid var(--line)}
.switch::after{content:"";position:absolute;left:2px;top:2px;width:20px;height:20px;border-radius:50%;background:#fff;
  box-shadow:0 1px 3px rgba(0,0,0,.22);transition:.2s var(--ease)}
.switch.on{background:var(--accent);border-color:transparent}
.switch.on::after{transform:translateX(18px)}

/* ============================================================
   3. 设置面板
   ============================================================ */
.sheet.settings{max-height:90dvh;height:90dvh}
.sheet.settings .sheet-body{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;
  padding-bottom:calc(28px + var(--safe-b))}
.sheet.settings .stabs{flex:0 0 auto}
#envList{padding-bottom:4px}
.stabs{display:flex;gap:4px;padding:2px 14px 12px;overflow-x:auto;scrollbar-width:none}
.stabs::-webkit-scrollbar{display:none}
.stabs button{flex:1 0 auto;height:34px;padding:0 13px;border-radius:10px;font-size:12.5px;color:var(--text-2);
  background:var(--surface-2);display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.stabs button.on{background:var(--accent);color:#fff;box-shadow:var(--accent-shadow)}
.stabs button .ic{width:15px;height:15px}
.sgroup{background:var(--surface-2);border:1px solid var(--line);border-radius:16px;padding:4px 12px;margin-bottom:12px}
.sgroup .srow{display:flex;align-items:center;gap:12px;padding:12px 2px;border-bottom:1px solid var(--line)}
.sgroup .srow:last-child{border-bottom:0}
.srow .si{width:32px;height:32px;border-radius:10px;background:var(--surface);display:flex;align-items:center;justify-content:center;color:var(--text-2);flex:0 0 auto;border:1px solid var(--line)}
.srow .stx{flex:1;min-width:0}
.srow .stx b{display:block;font-size:13.5px;font-weight:520}
.srow .stx small{display:block;font-size:11.5px;color:var(--text-3);margin-top:2px;line-height:1.45}
.srow .sval{font-size:12px;color:var(--text-3);flex:0 0 auto}
.sgroup .titled{font-size:11px;color:var(--text-3);padding:10px 4px 2px;letter-spacing:.5px}

.fieldrow{display:flex;gap:8px;margin:0 0 12px}
.fieldrow input{flex:1;min-width:0;height:44px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface-2);
  padding:0 13px;outline:none;font-size:14px}
.fieldrow input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.fieldrow .btn{flex:0 0 auto;padding:0 18px;width:auto}
.dlbtn{width:100%;height:48px;margin-top:14px;border-radius:14px;display:flex;align-items:center;
  justify-content:center;gap:7px;font-size:14px;font-weight:600;flex:0 0 auto}
.formlabel{font-size:11.5px;color:var(--text-3);margin:2px 0 7px;letter-spacing:.2px}
.notice{display:flex;align-items:center;gap:9px;padding:11px 13px;border-radius:13px;background:var(--danger-soft);
  color:var(--danger);font-size:12.5px;margin-bottom:12px}
.notice button{margin-left:auto;font-size:12px;font-weight:600;color:inherit;text-decoration:underline}
.notice.ok{background:rgba(18,183,106,.12);color:#0f9d58}
[data-theme="dark"] .notice.ok{color:#34d399}

.envrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 10px;padding:10px 4px;border-bottom:1px solid var(--line);align-items:center}
.envrow:last-child{border-bottom:0}
.envrow .el{font-size:12.5px;min-width:0}
.envrow .el small{display:block;font-size:11px;color:var(--text-3);margin-top:1px}
.envrow .ev{font-size:11.5px;color:var(--text-2);text-align:right;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.envrow .es{grid-column:2;justify-self:end;font-size:10.5px;padding:1px 7px;border-radius:20px;
  background:var(--surface-3);color:var(--text-2);margin-top:2px}
.es.good{background:rgba(18,183,106,.14);color:#0b9d5b}
.es.warn{background:rgba(247,144,9,.16);color:#b76e00}
.es.bad{background:var(--danger-soft);color:var(--danger)}
[data-theme="dark"] .es.good{color:#34d399}
[data-theme="dark"] .es.warn{color:#fbbf24}

.about-hero{display:flex;flex-direction:column;align-items:center;text-align:center;padding:18px 8px 8px}
.about-hero .am{position:relative;width:64px;height:64px;border-radius:20px;background:var(--grad-brand);
  display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:var(--accent-shadow-2);margin-bottom:12px;
  overflow:hidden;isolation:isolate}
.about-hero .am::before{content:'';position:absolute;left:0;right:0;top:0;height:52%;pointer-events:none;
  background:linear-gradient(180deg,rgba(255,255,255,.26),rgba(255,255,255,0))}
.about-hero .am::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.22)}
.about-hero .am i{position:relative;z-index:1;font-style:normal;font-size:27.5px;line-height:1;font-weight:750;
  user-select:none;-webkit-user-select:none;
  letter-spacing:-.8px;padding-right:2px;transform:translateY(-.5px);
  font-family:"SF Pro Display",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  text-shadow:0 1px 2px rgba(20,26,48,.22)}
.about-hero h3{margin:0 0 3px;font-size:17px}
.about-hero p{margin:0;font-size:12px;color:var(--text-3);max-width:320px;line-height:1.6}
.about-hero .ver{margin-top:8px;font-size:11.5px;color:var(--text-2);background:var(--surface-2);padding:3px 10px;border-radius:20px;border:1px solid var(--line)}
.about-list{background:var(--surface-2);border:1px solid var(--line);border-radius:16px;overflow:hidden;margin-top:14px}
.about-list div{display:flex;justify-content:space-between;gap:12px;padding:12px 14px;font-size:12.5px;border-bottom:1px solid var(--line)}
.about-list div:last-child{border-bottom:0}
.about-list span{color:var(--text-3)}
.about-list b{font-weight:520;text-align:right}
.about-foot{margin:20px 0 6px;padding:0 2px 2px;text-align:center;color:var(--text-3);letter-spacing:.2px}
.about-foot .af-rule{display:block;width:32px;height:2px;border-radius:2px;margin:0 auto 13px;background:var(--accent);opacity:.55}
.about-foot .af-copy{font-size:12px;line-height:1.65;font-weight:600;color:var(--text-2);font-variant-numeric:tabular-nums;letter-spacing:.1px}
.about-foot .af-line{font-size:11.5px;line-height:1.85;color:var(--text-2);opacity:.82}
.about-foot .af-mail{color:var(--accent);text-decoration:none;border-bottom:1px solid rgba(var(--accent-rgb),.35);padding-bottom:1px;word-break:break-all}
.about-foot .af-mail:active{opacity:.6}
@media (max-width:400px){.about-foot .af-copy{font-size:11.5px}.about-foot .af-line{font-size:11px}}

/* 详情面板：类型行 / 标签 */
.infobox{padding:2px 4px 10px}
.inforow{display:flex;gap:12px;align-items:flex-start;padding:11px 4px;border-bottom:1px solid var(--line);font-size:12.5px;line-height:1.5}
.inforow:last-child{border-bottom:0}
.ir-k{color:var(--text-3);flex:0 0 72px;white-space:nowrap}
.ir-v{flex:1;min-width:0;word-break:break-all;text-align:right;color:var(--text)}
.info-type{display:inline-flex;align-items:center;justify-content:flex-end;gap:6px;flex-wrap:wrap;max-width:100%}
.info-type b{font-weight:650;color:var(--text)}
.ftag{display:inline-flex;align-items:center;height:19px;padding:0 7px;border-radius:6px;font-size:10.5px;
  line-height:1;letter-spacing:.2px;color:var(--text-3);background:var(--surface-3);border:1px solid var(--line);white-space:nowrap}
.ftag-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums}
.ftag-on{color:var(--accent);background:rgba(var(--accent-rgb),.12);border-color:rgba(var(--accent-rgb),.32);font-weight:600}

/* ============================================================
   4. 编辑器
   ============================================================ */
.editor{position:fixed;inset:0;z-index:80;display:flex;flex-direction:column;background:var(--app);
  transform:translateY(3%);opacity:0;pointer-events:none;transition:.24s var(--ease)}
.editor.on{transform:none;opacity:1;pointer-events:auto}
.ed-head{flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:calc(8px + var(--safe-t)) 10px 8px;border-bottom:1px solid var(--line)}
.ed-tx{min-width:0;flex:1}
.ed-tx b{display:block;font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ed-tx small{display:block;font-size:11px;color:var(--text-3);margin-top:1px}
.ed-tools{display:flex;align-items:center;gap:4px;flex:0 0 auto}
.ed-save{height:34px;padding:0 14px;border-radius:10px;background:var(--accent);color:#fff;font-size:12.5px;font-weight:600;
  display:flex;align-items:center;gap:5px;box-shadow:var(--accent-shadow)}
.ed-save.dirty{background:var(--grad-btn)}
.ed-save:disabled{opacity:.55;box-shadow:none}
.ed-sub{flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:1px solid var(--line);background:var(--surface-2)}
.ed-sub .segsm{display:flex;gap:2px;background:var(--surface-3);padding:2px;border-radius:8px}
.ed-sub .segsm button{height:26px;padding:0 11px;border-radius:6px;font-size:11.5px;color:var(--text-2)}
.ed-sub .segsm button.on{background:var(--surface);color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.1)}
.ed-sub .sp{flex:1}
.ed-sub .tiny{font-size:11px;color:var(--text-3);font-variant-numeric:tabular-nums}
.ed-body{flex:1;min-height:0;position:relative;display:flex;background:var(--app)}
.ed-pane{flex:1;min-width:0;display:none;position:relative}
.ed-pane.on{display:flex}
.ed-plain{flex:1;width:100%;height:100%;border:0;outline:none;resize:none;background:transparent;color:var(--text);
  padding:14px 16px calc(24px + var(--safe-b));font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  font-size:13.5px;line-height:1.72;tab-size:2;white-space:pre;overflow:auto}
.adv-wrap{flex:1;display:flex;min-width:0;position:relative;overflow:hidden}
.adv-wrap{--ed-lh:23px}
.gutter{position:relative;flex:0 0 auto;align-self:stretch;width:48px;min-width:48px;box-sizing:border-box;
  background:var(--surface-2);border-right:1px solid var(--line);overflow:hidden;
  user-select:none;-webkit-user-select:none;pointer-events:none;
  -webkit-text-size-adjust:100%;text-size-adjust:100%}
.gut-in{position:absolute;left:0;top:0;right:0;will-change:transform;contain:layout style}
.gut-ln{display:block;height:var(--ed-lh);line-height:var(--ed-lh);padding:0 8px 0 3px;text-align:right;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:12px;
  color:var(--text-3);font-variant-numeric:tabular-nums;letter-spacing:0;white-space:nowrap;overflow:hidden}
.adv-scroll{flex:1;position:relative;overflow:auto;min-width:0}
.adv-inner{position:relative;min-width:100%;min-height:100%}
.hl,.adv-ta{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:13.5px;
  line-height:var(--ed-lh);tab-size:2;letter-spacing:0;padding:12px 18px 60px 14px;margin:0;white-space:pre;word-break:normal;overflow-wrap:normal}
.hl{position:absolute;left:0;top:0;right:auto;bottom:auto;pointer-events:none;color:var(--text);z-index:1;will-change:transform}
.adv-ta{position:relative;z-index:2;display:block;width:100%;min-height:100%;border:0;outline:none;resize:none;
  background:transparent;color:transparent;caret-color:var(--accent);overflow:hidden}
.adv-ta::selection{background:rgba(var(--accent-rgb),.28);color:transparent}
.adv-ta.solid{color:var(--text)}
.adv-ta.typing{color:var(--text)}
.adv-ta.ime{color:var(--text)}
.ed-mask{position:absolute;inset:0;z-index:9;display:none;align-items:center;justify-content:center;flex-direction:column;gap:10px;
  background:var(--app);color:var(--text-3);font-size:12px}
.ed-mask.on{display:flex}
.ed-spin{width:22px;height:22px;border-radius:50%;border:2px solid var(--surface-3);border-top-color:var(--accent);
  animation:edspin .7s linear infinite}
@keyframes edspin{to{transform:rotate(360deg)}}
.ed-perf{display:none;height:19px;padding:0 7px;border-radius:6px;background:rgba(var(--accent-rgb),.12);color:var(--accent);
  font-size:10px;line-height:19px;white-space:nowrap;letter-spacing:.2px}
.ed-perf.on{display:inline-block}
.tk-key{color:#7c3aed;font-weight:600}
.tk-str{color:#0f9d58}
.tk-num{color:#d97706}
.tk-com{color:#96a0b2;font-style:italic}
.tk-tag{color:#2563eb}
.tk-attr{color:#db2777}
.tk-fn{color:#0891b2}
[data-theme="dark"] .tk-key{color:#c4b5fd}
[data-theme="dark"] .tk-str{color:#86efac}
[data-theme="dark"] .tk-num{color:#fcd34d}
[data-theme="dark"] .tk-com{color:#64748b}
[data-theme="dark"] .tk-tag{color:#93c5fd}
[data-theme="dark"] .tk-attr{color:#f9a8d4}
[data-theme="dark"] .tk-fn{color:#67e8f9}
.findbar{display:none;align-items:center;gap:6px;padding:7px 10px;background:var(--surface-2);border-bottom:1px solid var(--line);flex-wrap:wrap}
.findbar.on{display:flex}
.findbar input{flex:1;min-width:90px;height:32px;border-radius:8px;border:1px solid var(--line-2);background:var(--surface);
  padding:0 9px;font-size:12.5px;outline:none}
.findbar input:focus{border-color:var(--accent)}
.findbar button{height:32px;padding:0 10px;border-radius:8px;font-size:12px;color:var(--text-2);background:var(--surface);border:1px solid var(--line)}
.findbar .cnt{font-size:11px;color:var(--text-3);min-width:44px;text-align:center}
.ed-status{flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:5px 14px calc(5px + var(--safe-b));
  border-top:1px solid var(--line);font-size:11px;color:var(--text-3);background:var(--surface-2);font-variant-numeric:tabular-nums}
.ed-status .sp{flex:1}
.ed-toolrow{flex:0 0 auto;display:flex;align-items:center;gap:6px;padding:6px 10px;border-bottom:1px solid var(--line);
  background:var(--surface);overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.ed-toolrow::-webkit-scrollbar{display:none}
.ed-toolrow button{flex:0 0 auto;display:inline-flex;align-items:center;gap:4px;height:28px;padding:0 10px;border-radius:8px;
  font-size:11.5px;color:var(--text-2);background:var(--surface-2);border:1px solid var(--line);white-space:nowrap}
.ed-toolrow button.on{background:rgba(var(--accent-rgb),.12);border-color:rgba(var(--accent-rgb),.35);color:var(--accent);font-weight:600}
.ed-toolrow button:disabled{opacity:.4}
.ed-toolrow .tsep{flex:0 0 auto;width:1px;height:16px;background:var(--line)}
/* 解压方式选择（当前文件夹 / 新建文件夹） */
.xmode{display:flex;flex-direction:column;gap:8px;margin:2px 0 14px}
.xmode-item{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:14px;border:1px solid var(--line);
  background:var(--surface-2);text-align:left;color:var(--text);width:100%}
.xmode-item:active{transform:scale(.995)}
.xmode-item.on{border-color:rgba(var(--accent-rgb),.55);background:rgba(var(--accent-rgb),.10)}
.xmode-item .xmi{flex:0 0 auto;width:34px;height:34px;border-radius:11px;display:flex;align-items:center;justify-content:center;
  background:rgba(var(--accent-rgb),.14);color:var(--accent)}
.xmode-item .xmt{min-width:0;flex:1;display:flex;flex-direction:column;gap:2px}
.xmode-item .xmt b{font-size:13px;font-weight:600;line-height:1.35}
.xmode-item .xmt small{font-size:11px;color:var(--text-3);line-height:1.45;white-space:normal}
.xmode-item .xmk{flex:0 0 auto;width:17px;height:17px;border-radius:50%;border:1.5px solid var(--line-2);color:transparent;
  display:flex;align-items:center;justify-content:center}
.xmode-item.on .xmk{background:var(--accent);border-color:var(--accent);color:#fff}
.xmode-item .xmk svg{width:11px;height:11px;stroke-width:3}
.cmpfield[hidden]{display:none!important}
.xmode ~ .sheet-foot{display:flex;gap:10px;padding:6px 0 2px}
.xmode ~ .sheet-foot .btn{flex:1}
/* 编码面板：编辑器内联浮层（普通 / 高级编辑器通用） */
.ed-enc{position:absolute;z-index:24;display:none;flex-direction:column;width:322px;width:min(322px,calc(100% - 16px));
  max-height:calc(100% - 20px);background:var(--surface);border:1px solid var(--line);border-radius:14px;
  box-shadow:var(--shadow-2);overflow:hidden}
.ed-enc.on{display:flex;animation:encin .16s var(--ease)}
@keyframes encin{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.ed-enc-head{display:flex;align-items:center;gap:8px;padding:12px 12px 8px}
.ed-enc-head b{font-size:13.5px;font-weight:650;color:var(--text)}
.ed-enc-head .cur{flex:1;min-width:0;text-align:right;font-size:11px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ed-enc-x{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--text-3);flex:0 0 auto}
.ed-enc-x:active{background:var(--surface-3)}
.ed-enc-tabs{display:flex;gap:2px;margin:0 12px 8px;padding:2px;border-radius:9px;background:var(--surface-3);flex:0 0 auto}
.ed-enc-tabs button{flex:1;height:28px;border-radius:7px;font-size:11.5px;color:var(--text-2)}
.ed-enc-tabs button.on{background:var(--surface);color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.08)}
.ed-enc-list{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:0 6px 4px;-webkit-overflow-scrolling:touch}
.ed-enc-item{display:flex;align-items:center;gap:8px;width:100%;height:38px;padding:0 8px;border-radius:9px;text-align:left;color:var(--text)}
.ed-enc-item .nm{flex:1;min-width:0;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ed-enc-item .tag{flex:0 0 auto;font-size:10px;color:var(--text-3);border:1px solid var(--line);border-radius:5px;padding:1px 5px}
.ed-enc-item .ck{flex:0 0 auto;width:16px;height:16px;color:var(--accent);display:flex;align-items:center;justify-content:center}
.ed-enc-item.on{background:rgba(var(--accent-rgb),.10);color:var(--accent);font-weight:600}
.ed-enc-item:active{background:var(--surface-2)}
.ed-enc-note{padding:6px 14px 2px;font-size:10.5px;line-height:1.55;color:var(--text-3);flex:0 0 auto}
.ed-enc-foot{padding:8px 12px 12px;flex:0 0 auto}
.ed-enc-go{width:100%;height:38px;border-radius:10px;background:var(--accent);color:#fff;font-size:12.5px;font-weight:650}
.ed-enc-go:disabled{opacity:.45}
.ed-encchip{flex:0 0 auto;height:20px;padding:0 7px;border-radius:6px;border:1px solid var(--line);background:var(--surface);
  color:var(--text-3);font-size:10px;line-height:1;letter-spacing:.2px;max-width:96px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ed-encchip.on{border-color:rgba(var(--accent-rgb),.45);background:rgba(var(--accent-rgb),.12);color:var(--accent);font-weight:600}
.ed-plain.wrapon-txt{white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
.adv-wrap.wrapon .gutter{display:none}
.adv-wrap.wrapon .hl{display:none}
.adv-wrap.wrapon .adv-scroll{overflow:hidden}
.adv-wrap.wrapon .adv-inner{height:100%;min-height:100%}
.adv-wrap.wrapon .adv-ta{position:absolute;inset:0;width:100%;height:100%;overflow:auto;
  white-space:pre-wrap;overflow-wrap:anywhere;color:var(--text);padding-bottom:60px}
.secbox{display:flex;flex-direction:column;gap:8px;width:100%;max-width:460px;margin:0 auto 8px}
.secfield{width:100%;height:44px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface-2);
  padding:0 13px;outline:none;color:var(--text);font-size:13.5px}
.secfield:focus{border-color:var(--accent)}
.seccenter{width:100%;height:46px;display:inline-flex;align-items:center;justify-content:center;gap:6px;text-align:center}
.sechint{font-size:11px;color:var(--text-3);text-align:center;margin-top:2px}
.mvpath{font-size:11.5px;color:var(--text-3);padding:0 2px 6px;word-break:break-all}
.mvlist{max-height:44vh;overflow-y:auto;border:1px solid var(--line);border-radius:14px;background:var(--surface-2)}

/* ============================================================
   5. 预览
   ============================================================ */
.viewer{position:fixed;inset:0;z-index:78;display:flex;flex-direction:column;background:rgba(6,8,12,.97);color:#eef2f9;
  opacity:0;pointer-events:none;transition:opacity .2s}
.viewer.on{opacity:1;pointer-events:auto}
.v-head{flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:calc(10px + var(--safe-t)) 12px 10px}
.v-head .vt{min-width:0;flex:1}
.v-head b{display:block;font-size:13.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.v-head small{display:block;font-size:11px;color:#8b97ac;margin-top:1px}
.v-head button{width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;color:#dbe3ef}
.v-head button:hover{background:rgba(255,255,255,.1)}
.v-body{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;overflow:auto;padding:8px 12px calc(24px + var(--safe-b))}
.v-body img{max-width:100%;max-height:100%;object-fit:contain;border-radius:10px}
.v-body video,.v-body audio{max-width:100%;border-radius:12px;outline:none}
.v-body video{max-height:100%}
.v-body iframe{width:100%;height:100%;border:0;background:#fff;border-radius:12px}
.v-body pre{width:100%;height:100%;overflow:auto;margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;
  font-size:12.5px;line-height:1.7;color:#cdd6e5;white-space:pre-wrap;word-break:break-word}
/* ---------- 媒体预览（图片 / 音频 / 视频 / HLS） ---------- */
.pv-stage{position:relative;width:100%;height:100%;min-height:0;display:flex;align-items:center;justify-content:center}
.pv-video{width:100%;height:100%;max-height:100%;background:#000;border-radius:12px;object-fit:contain;outline:none}
.pv-badge{position:absolute;top:8px;left:8px;display:inline-flex;align-items:center;height:22px;padding:0 9px;
  border-radius:999px;background:rgba(10,14,20,.66);border:1px solid rgba(255,255,255,.14);color:#cfdaea;
  font-size:10.5px;letter-spacing:.06em;-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);pointer-events:none}
.pv-imgwrap{position:relative;width:100%;height:100%;min-height:0;display:flex;align-items:center;justify-content:center;
  overflow:hidden;touch-action:none;-webkit-user-select:none;user-select:none}
.pv-img{max-width:100%;max-height:100%;object-fit:contain;border-radius:12px;transform-origin:center center;
  will-change:transform;transition:transform .12s ease-out;-webkit-user-drag:none}
.pv-imgwrap.dragging .pv-img{transition:none}
.pv-imgwrap.zoomed{cursor:grab}
.pv-hint{position:absolute;left:50%;bottom:12px;transform:translateX(-50%);padding:5px 12px;border-radius:999px;
  background:rgba(12,16,24,.72);border:1px solid rgba(255,255,255,.1);color:#c6d1e2;font-size:11px;white-space:nowrap;
  opacity:1;transition:opacity .6s ease;pointer-events:none}
.pv-hint.fade{opacity:0}
.pv-audio{width:min(420px,100%);display:flex;flex-direction:column;align-items:center;gap:9px;text-align:center;padding:0 2px}
.pv-disc{width:96px;height:96px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#bcd6ff;
  background:radial-gradient(circle at 50% 34%,rgba(90,169,255,.30),rgba(90,169,255,.07) 62%,rgba(255,255,255,.02));
  border:1px solid rgba(255,255,255,.1);box-shadow:0 10px 30px -14px rgba(0,0,0,.9)}
.pv-disc .ic{width:34px;height:34px}
.pv-disc.spin{animation:pvSpin 9s linear infinite}
@keyframes pvSpin{to{transform:rotate(360deg)}}
.pv-atitle{font-size:13.5px;font-weight:600;line-height:1.5;word-break:break-all;max-width:100%}
.pv-asub{font-size:11px;color:#8b97ac}
.pv-audio audio{width:100%;height:44px;margin-top:4px;border-radius:12px;outline:none}
.pv-fail{max-width:340px;display:flex;flex-direction:column;align-items:center;gap:7px;text-align:center;padding:0 8px}
.pv-fail-ico{width:76px;height:76px;border-radius:22px;display:flex;align-items:center;justify-content:center;
  background:rgba(255,255,255,.07);color:#9fb0c7;margin-bottom:3px}
.pv-fail-ico .ic{width:30px;height:30px}
.pv-fail-msg{font-size:13px;line-height:1.6;margin:0;color:#e6edf8}
.pv-fail-tip{font-size:11.5px;line-height:1.6;margin:0;color:#8b97ac}
.pv-fail-btns{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:8px}
.pv-btn{height:40px;padding:0 18px;border-radius:11px;font-size:13px;color:#dbe3ef;background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.1);transition:transform .12s ease,background .16s}
.pv-btn.on{background:rgba(90,169,255,.18);border-color:rgba(90,169,255,.42);color:#cfe4ff}
.pv-btn:active{transform:scale(.97)}
@media (prefers-reduced-motion:reduce){.pv-disc.spin{animation:none}.pv-img{transition:none}.pv-btn{transition:none}}
/* ---------- ZIP 压缩包内容浏览 ---------- */
.v-body.zip-body{padding:0;display:block;overflow:hidden;align-items:stretch;justify-content:flex-start}
.zipbox{width:100%;height:100%;min-height:0;display:flex;flex-direction:column}
.zip-top{flex:0 0 auto;padding:2px 12px 10px;border-bottom:1px solid rgba(255,255,255,.07)}
.zip-stats{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.zip-chip{display:inline-flex;align-items:center;gap:4px;height:24px;padding:0 9px;border-radius:8px;
  background:rgba(255,255,255,.07);color:#aab6c8;font-size:10.5px;white-space:nowrap}
.zip-chip b{color:#eef2f9;font-weight:600;font-variant-numeric:tabular-nums}
.zip-nav{display:flex;align-items:center;gap:6px;min-width:0}
.zip-up{flex:0 0 auto;width:32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center;
  background:rgba(90,169,255,.15);color:#a9cfff;transition:background .16s,color .16s}
.zip-up .ic{width:17px;height:17px}
.zip-up:hover{background:rgba(90,169,255,.24)}
.zip-up:active{background:rgba(90,169,255,.32);color:#fff}
.zip-up:focus-visible{outline:2px solid rgba(90,169,255,.65);outline-offset:1px}
.zip-up[hidden]{display:none}
.zip-crumbs{flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:2px;min-height:32px;overflow-x:auto;overflow-y:hidden;
  white-space:nowrap;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.zip-crumbs::-webkit-scrollbar{display:none}
.zip-crumb{flex:0 0 auto;height:30px;padding:0 9px;border-radius:9px;font-size:12px;line-height:30px;color:#a6b3c6;
  max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:background .16s,color .16s}
.zip-crumb .ic{width:12px;height:12px;vertical-align:-2px;margin-left:4px;opacity:.72}
.zip-crumb[data-zdir]:hover,.zip-crumb[data-zdir]:focus-visible{background:rgba(255,255,255,.07);color:#e6edf8}
.zip-crumb.on{color:#eef2f9;background:rgba(255,255,255,.09);font-weight:600}
.zip-crumb:active{background:rgba(255,255,255,.15)}
.zip-crumb-sep{flex:0 0 auto;color:#5c6a80;font-size:10px;margin:0 1px}
.zip-tools{display:flex;align-items:center;gap:8px;margin-top:8px}
.zip-search{position:relative;flex:1;min-width:0}
.zip-search .ic{position:absolute;left:11px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:#7f8ca1;pointer-events:none}
.zip-search input{width:100%;height:38px;border-radius:11px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.09);
  padding:0 34px 0 33px;color:#eef2f9;font-size:12.5px;outline:none;-webkit-appearance:none}
.zip-search input::placeholder{color:#7c889c}
.zip-search input::-webkit-search-cancel-button{-webkit-appearance:none}
.zip-search input:focus{border-color:rgba(90,169,255,.55);background:rgba(90,169,255,.09)}
.zip-clear{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:9px;
  display:flex;align-items:center;justify-content:center;color:#9aa6ba}
.zip-clear[hidden]{display:none}
.zip-list{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;padding:6px 6px calc(20px + var(--safe-b))}
.zip-row{display:flex;align-items:center;gap:10px;width:100%;min-height:54px;padding:7px 8px;border-radius:12px;text-align:left;color:#eef2f9;cursor:pointer}
.zip-row:active,.zip-row:focus-visible{background:rgba(255,255,255,.07)}
.zip-ico{flex:0 0 auto;width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;
  background:rgba(255,255,255,.07);color:#9fb0c7}
.zip-ico .ic{width:18px;height:18px}
.zip-ico.dir{color:#8fc0ff;background:rgba(90,169,255,.13)}
.zip-ico.zip{color:#ffcf8a;background:rgba(255,183,77,.13)}
.zip-info{flex:1;min-width:0}
.zip-name{display:block;font-size:12.8px;line-height:1.35;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.zip-meta{display:block;margin-top:2px;font-size:10.5px;color:#8390a4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.zip-dl{flex:0 0 auto;width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#9fb0c7}
.zip-dl:active{background:rgba(255,255,255,.12);color:#fff}
.zip-dl .ic{width:16px;height:16px}
.zip-lock{flex:0 0 auto;width:30px;height:30px;display:flex;align-items:center;justify-content:center;color:#7f8ca1}
.zip-lock .ic{width:14px;height:14px}
.zip-note{font-size:10.5px;color:#7f8ca1;padding:8px 10px 4px;line-height:1.5}
.zip-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:48px 20px;color:#8390a4;font-size:12px;text-align:center}
.zip-empty .ic{width:34px;height:34px;color:#59677d}
.zip-more{display:flex;justify-content:center;padding:10px}
.zip-more button{height:36px;padding:0 18px;border-radius:10px;background:rgba(255,255,255,.08);color:#c7d2e5;font-size:12px}
.zip-view{width:100%;height:100%;display:flex;flex-direction:column;min-height:0}
.zip-vhead{flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.07)}
.zip-back{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#dbe3ef;flex:0 0 auto}
.zip-back:active{background:rgba(255,255,255,.1)}
.zip-vname{flex:1;min-width:0}
.zip-vname b{display:block;font-size:12.8px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.zip-vname small{display:block;font-size:10.5px;color:#8390a4;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.zip-vbody{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;overflow:auto;padding:10px 12px calc(18px + var(--safe-b))}
.zip-vbody img{max-width:100%;max-height:100%;object-fit:contain;border-radius:10px}
.zip-vbody video{max-width:100%;max-height:100%;border-radius:12px}
.zip-vbody audio{width:100%;max-width:520px}
.zip-vbody iframe{width:100%;height:100%;border:0;border-radius:10px;background:#fff}
.zip-pre{width:100%;height:100%;overflow:auto;margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.75;
  color:#cdd6e5;white-space:pre-wrap;word-break:break-word;tab-size:4}
.zip-missing{display:flex;flex-direction:column;align-items:center;gap:12px;color:#9aa6ba;font-size:12.5px;text-align:center;padding:24px}
.zip-missing .ic{width:38px;height:38px;color:#59677d}
.zip-btn{height:40px;padding:0 18px;border-radius:11px;background:rgba(90,169,255,.18);color:#9fcbff;font-size:12.5px;font-weight:600}
.zip-spin{width:26px;height:26px;border-radius:50%;border:2px solid rgba(255,255,255,.16);border-top-color:#8fc0ff;animation:zipspin .8s linear infinite}
@keyframes zipspin{to{transform:rotate(360deg)}}


/* ---------- 首次使用引导浮层 ---------- */
.sgm{position:fixed;inset:0;z-index:130;display:none;overflow-y:auto;overscroll-behavior:contain;
  padding:calc(16px + var(--safe-t)) 12px calc(16px + var(--safe-b));background:rgba(6,8,14,.72);
  -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}
.sgm.on{display:block}
.sgm-card{position:relative;width:100%;max-width:420px;margin:auto;background:var(--surface);
  border:1px solid var(--line-2);border-radius:22px;box-shadow:var(--shadow-2);padding:18px 18px 16px;
  color:var(--text);animation:sgmin .24s var(--ease) both}
@keyframes sgmin{from{opacity:0;transform:translateY(8px) scale(.99)}to{opacity:1;transform:none}}
.sgm-head{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.sgm-mark{flex:0 0 auto;width:40px;height:40px;border-radius:13px;display:flex;align-items:center;justify-content:center;
  background:var(--grad-brand);box-shadow:var(--brand-shadow);color:#fff}
.sgm-mark .ic{width:21px;height:21px}
.sgm-ht{flex:1;min-width:0}
.sgm-ht b{display:block;font-size:14.5px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sgm-ht span{display:block;margin-top:2px;font-size:11px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sgm-x{flex:0 0 auto;width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;color:var(--text-3)}
.sgm-x:active{background:var(--surface-2)}
.sgm-body{display:block}
.sgm-h{font-size:17px;line-height:1.35;font-weight:680;margin:0 0 6px}
.sgm-lead{margin:0 0 14px;font-size:12.2px;line-height:1.65;color:var(--text-2)}
.sgm-list{list-style:none;margin:0 0 16px;padding:0;display:flex;flex-direction:column;gap:8px}
.sgm-li{display:flex;align-items:flex-start;gap:9px;padding:9px 11px;border-radius:12px;background:var(--surface-2);
  border:1px solid var(--line);font-size:12px;line-height:1.55;color:var(--text-2)}
.sgm-li .ic{flex:0 0 auto;width:15px;height:15px;margin-top:2px;color:var(--accent)}
.sgm-field{margin-bottom:10px}
.sgm-field>label{display:block;margin:0 2px 6px;font-size:11.5px;color:var(--text-2)}
.sgm-inp{position:relative}
.sgm-inp input{width:100%;height:46px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface-2);
  color:var(--text);padding:0 44px 0 13px;font-size:16px;outline:none;-webkit-appearance:none}
.sgm-inp input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.sgm-eye{position:absolute;right:3px;top:3px;width:40px;height:40px;border-radius:10px;display:flex;
  align-items:center;justify-content:center;color:var(--text-3)}
.sgm-eye:active{background:var(--surface-3)}
.sgm-meter{display:flex;align-items:center;gap:4px;margin-top:7px}
.sgm-meter i{flex:1 1 0;height:4px;border-radius:2px;background:var(--surface-3)}
.sgm-meter span{flex:0 0 auto;min-width:34px;text-align:right;font-size:10.5px;color:var(--text-3)}
.sgm-meter.m1 i:nth-child(1){background:#f04438}
.sgm-meter.m2 i:nth-child(-n+2){background:#f79009}
.sgm-meter.m3 i:nth-child(-n+3){background:#3b82f6}
.sgm-meter.m4 i{background:#12b76a}
.sgm-rules{list-style:none;display:flex;flex-wrap:wrap;gap:4px 10px;margin:8px 2px 0;padding:0}
.sgm-rules li{position:relative;padding-left:12px;font-size:10.6px;line-height:1.6;color:var(--text-3)}
.sgm-rules li::before{content:"";position:absolute;left:0;top:6px;width:5px;height:5px;border-radius:50%;background:var(--line-2)}
.sgm-rules li.ok{color:var(--ok)}
.sgm-rules li.ok::before{background:var(--ok)}
.sgm-err{min-height:16px;margin:8px 2px 0;font-size:11.5px;line-height:1.5;color:var(--danger)}
.sgm-acts{display:flex;gap:8px;margin-top:6px}
.sgm-acts .btn{height:46px;font-size:13.5px}
.sgm-acts .btn-ghost{flex:0 0 38%}
.sgm-acts .btn-primary{flex:1 1 auto}
.sgm-note{margin:9px 2px 0;font-size:10.4px;line-height:1.6;color:var(--text-3);text-align:center}
.sgm-ok{display:flex;flex-direction:column;align-items:center;text-align:center;padding:6px 0 2px}
.sgm-tick{width:60px;height:60px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  background:rgba(18,183,106,.13);color:var(--ok);margin-bottom:12px;animation:sgmPop .4s var(--ease) both}
.sgm-tick .ic{width:28px;height:28px}
@keyframes sgmPop{from{transform:scale(.6);opacity:0}to{transform:scale(1);opacity:1}}
.sgm-acc{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;margin:4px 0 14px;
  padding:11px 13px;border-radius:12px;background:var(--surface-2);border:1px solid var(--line);font-size:11.5px;color:var(--text-3)}
.sgm-acc b{font-size:13px;color:var(--text);word-break:break-all;text-align:right}
body.sgm-open{overflow:hidden}

/* ============================================================
   6. 进度与提示
   ============================================================ */
.progress{position:fixed;left:50%;bottom:calc(96px + var(--safe-b));z-index:70;transform:translate(-50%,20px);
  min-width:220px;max-width:calc(100vw - 40px);padding:11px 14px;border-radius:14px;background:var(--surface);
  border:1px solid var(--line);box-shadow:var(--shadow-2);opacity:0;pointer-events:none;transition:.2s}
.progress.on{opacity:1;transform:translate(-50%,0)}
.progress .pt{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--text-2);margin-bottom:8px}
.progress .pt b{margin-left:auto;color:var(--text);font-variant-numeric:tabular-nums}
.progress .pb{height:5px;border-radius:5px;background:var(--surface-3);overflow:hidden}
.progress .pb i{display:block;height:100%;width:0;border-radius:5px;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .2s}

.toaster{position:fixed;left:50%;bottom:calc(152px + var(--safe-b));z-index:90;transform:translateX(-50%);
  display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none;width:max-content;max-width:calc(100vw - 32px)}
.toast{background:rgba(16,20,28,.94);color:#fff;font-size:12.5px;padding:10px 16px;border-radius:12px;
  box-shadow:0 10px 26px rgba(0,0,0,.3);opacity:0;transform:translateY(8px);transition:.22s var(--ease);
  max-width:100%;text-align:center;line-height:1.5;word-break:break-word}
[data-theme="dark"] .toast{background:rgba(238,242,249,.96);color:#0b1019}
.toast.on{opacity:1;transform:none}
.toast.err{background:#b42318}
[data-theme="dark"] .toast.err{background:#ff6b74;color:#1a0505}


/* ---------- 网格视图 ---------- */
.list.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(94px,1fr));gap:9px;
  background:transparent;border:0;box-shadow:none;padding:2px 0;border-radius:0;overflow:visible}
.list.grid .row{display:flex;flex-direction:column;align-items:center;height:auto;padding:15px 6px 12px;
  border:1px solid var(--line);border-radius:16px;background:var(--surface);gap:9px;box-shadow:var(--shadow-1)}
.list.grid .r-lead{width:46px;height:46px}
.list.grid .r-ico{width:46px;height:46px;border-radius:14px}
.list.grid .r-ico .ic{width:24px;height:24px}
.list.grid .r-main{align-items:center;text-align:center;width:100%}
.list.grid .r-name{font-size:12px;max-width:100%;text-align:center;font-weight:500;line-height:1.35;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal;overflow:hidden}
.list.grid .r-meta{display:none}
.list.grid .r-col,.list.grid .r-act{display:none}
.list.grid .r-check{inset:0}
.list.grid.selecting .r-ico{opacity:.35}
.list.hide-perm .r-perm{display:none}
.thead.hide-perm .th-perm{display:none}

/* ---------- 仓库版本列表 ---------- */
.refitem{display:flex;align-items:center;gap:8px;width:100%;padding:11px 12px;font-size:12.5px;
  text-align:left;border-bottom:1px solid var(--line);color:var(--text)}
.refitem:last-child{border-bottom:0}
.refitem small{margin-left:auto;font-size:10px;color:var(--text-3);background:var(--surface-3);padding:1px 6px;border-radius:6px}
.refitem.on{background:var(--accent-soft);color:var(--accent);font-weight:600}
.refitem.on small{color:var(--accent);background:rgba(var(--accent-rgb),.16)}

/* ---------- GitHub 仓库介绍与版本说明 ---------- */
.ghhead{display:flex;align-items:center;gap:10px;padding:2px 2px 10px}
.ghhead .ghi{width:38px;height:38px;border-radius:12px;background:var(--surface-2);border:1px solid var(--line);
  display:flex;align-items:center;justify-content:center;color:var(--text-2);flex:0 0 auto}
.ghhead .ght{min-width:0;flex:1}
.ghhead b{display:block;font-size:13.5px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ghhead small{display:block;font-size:11px;color:var(--text-3);margin-top:2px;line-height:1.45;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;word-break:break-word}
.ghcard{background:var(--surface-2);border:1px solid var(--line);border-radius:14px;padding:11px 12px;margin:0 0 10px}
.ghcard .ghc-t{display:flex;align-items:center;gap:6px;font-size:11.5px;font-weight:650;color:var(--text);margin-bottom:7px}
.ghcard .ghc-t .ic{width:14px;height:14px;color:var(--accent);flex:0 0 auto}
.ghcard p{margin:0;font-size:12px;line-height:1.68;color:var(--text-2);word-break:break-word}
.ghchips{display:flex;flex-wrap:wrap;gap:5px;margin-top:9px}
.ghchips span{display:inline-flex;align-items:center;gap:3px;max-width:100%;font-size:10.5px;line-height:1.5;
  padding:2px 7px;border-radius:20px;background:var(--surface-3);color:var(--text-2);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ghchips span .ic{width:11px;height:11px;flex:0 0 auto}
.ghsteps{display:flex;flex-direction:column;gap:7px;margin:0;padding:0;list-style:none}
.ghsteps li{display:flex;gap:7px;font-size:11.5px;line-height:1.55;color:var(--text-2);word-break:break-word}
.ghbadge{flex:0 0 auto;font-size:9.5px;font-weight:600;letter-spacing:.3px;padding:2px 7px;border-radius:20px}
.ghbadge.good{background:rgba(18,183,106,.14);color:#0b9d5b}
.ghbadge.warn{background:rgba(247,144,9,.16);color:#b76e00}
[data-theme="dark"] .ghbadge.good{color:#34d399}
[data-theme="dark"] .ghbadge.warn{color:#fbbf24}
.ghsteps li i{flex:0 0 auto;width:16px;height:16px;margin-top:1px;border-radius:50%;background:rgba(var(--accent-rgb),.14);
  color:var(--accent);font-size:9.5px;font-style:normal;display:flex;align-items:center;justify-content:center}
.ghsum{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin:0 2px 7px;font-size:10.5px;color:var(--text-3)}
.ghsum b{font-weight:600;color:var(--text-2)}
.ghsum .dot{width:3px;height:3px;border-radius:50%;background:var(--line-2)}
.ghverbox{border:1px solid var(--line);border-radius:14px;background:var(--surface-2);overflow:hidden;margin-bottom:10px}
.ghver{display:flex;align-items:flex-start;gap:9px;width:100%;padding:10px 11px;border-bottom:1px solid var(--line);
  text-align:left;color:var(--text);transition:background .14s}
.ghver:last-child{border-bottom:0}
.ghver:hover{background:var(--surface-3)}
.ghver .gv-main{display:block;min-width:0;flex:1}
.ghver .gv-n{display:flex;align-items:center;gap:6px;min-width:0;font-size:12.5px;font-weight:600}
.ghver .gv-n em{flex:0 0 auto;font-style:normal;font-size:9px;font-weight:500;padding:0 5px;border-radius:5px;
  background:var(--surface-3);color:var(--text-3);line-height:15px}
.ghver .gv-n span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ghver .gv-d{font-size:10.5px;line-height:1.55;color:var(--text-3);margin-top:3px;word-break:break-word;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ghver .gv-b{flex:0 0 auto;margin-top:2px;font-size:9px;padding:1px 6px;border-radius:6px;line-height:15px;
  background:var(--surface-3);color:var(--text-3);white-space:nowrap}
.ghver.on{background:var(--accent-soft)}
.ghver.on .gv-n{color:var(--accent)}
.ghver.on .gv-n em,.ghver.on .gv-b{background:rgba(var(--accent-rgb),.16);color:var(--accent)}
.ghdetail{border:1px solid var(--line);border-radius:14px;background:var(--surface-2);padding:11px 12px;margin-bottom:10px}
.ghdetail .gd-h{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px}
.ghdetail .gd-h b{font-size:12.5px;font-weight:650;word-break:break-all}
.ghdetail .gd-h em{font-style:normal;font-size:9px;padding:1px 6px;border-radius:6px;line-height:15px;
  background:rgba(var(--accent-rgb),.14);color:var(--accent)}
.ghdetail .gd-h a{margin-left:auto;font-size:10.5px;color:var(--accent);text-decoration:none;
  display:inline-flex;align-items:center;gap:3px;flex:0 0 auto}
.ghdetail .gd-h a .ic{width:11px;height:11px}
.ghdetail .gd-m{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:10.5px;color:var(--text-3);margin-bottom:6px}
.ghdetail p{margin:0;font-size:11.5px;line-height:1.7;color:var(--text-2);white-space:pre-wrap;
  word-break:break-word;max-height:120px;overflow-y:auto;overscroll-behavior:contain}
.gh-dlbar{position:sticky;bottom:0;z-index:2;padding:9px 0 2px;background:var(--surface);border-top:1px solid var(--line)}
.gh-dlbar .dlbtn{margin-top:8px}
/* 下载方式：在「设置 · 通用」中配置，这里显示当前方式并可跳转修改 */
.ghmode{display:flex;align-items:center;gap:10px;width:100%;text-align:left;padding:9px 11px;margin-bottom:2px;
  border:1px solid var(--line);border-radius:14px;background:var(--surface-2);transition:.16s}
.ghmode:active{transform:scale(.99)}
.ghmode .gm-ic{flex:0 0 auto;width:30px;height:30px;border-radius:9px;display:grid;place-items:center;
  background:rgba(var(--accent-rgb),.12);color:var(--accent)}
.ghmode .gm-ic .ic{width:16px;height:16px}
.ghmode .gm-tx{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:2px}
.ghmode .gm-tx b{font-size:12.5px;font-weight:600;color:var(--text)}
.ghmode .gm-tx small{font-size:10.5px;line-height:1.5;color:var(--text-3);
  word-break:break-word;overflow-wrap:anywhere}
.ghmode .gm-go{flex:0 0 auto;font-size:10.5px;color:var(--accent)}
.btn .ic{flex:0 0 auto}

/* ============================================================
   7. 桌面适配
   ============================================================ */
@media (min-width:900px){
  .sidebar{display:flex}
  .main{background:var(--app);border-radius:0}
  .topbar{height:70px;padding:0 26px;gap:12px;background:var(--app);border-bottom:1px solid var(--line)}
  .topbar.scrolled{background:var(--app);backdrop-filter:none}
  .tb-title{font-size:20px}
  .tb-sub{font-size:12px}
  .iconbtn{width:36px;height:36px;border-radius:10px}
  .scroll{padding:14px 26px 104px}
  .scroll.clip-on{padding-bottom:152px}
  .hero{margin:2px 0 16px;padding:22px 24px 20px;border-radius:24px}
  .hero-value{font-size:30px}
  .chips{padding-bottom:14px}
  .list{background:transparent;border:0;box-shadow:none;border-radius:0}
  .listhead{padding:0 2px 10px}
  .thead{display:flex}
  .row{grid-template-columns:34px minmax(0,1fr) 88px 132px 132px 40px;height:52px;border-radius:12px;
    border-bottom:0;padding:0 8px;background:transparent}
  .row:hover{background:var(--surface-2)}
  .row.selected{background:var(--accent-soft)}
  .r-meta{display:none}
  .r-col{display:block}
  .r-col.r-time{display:block}
  .r-name{font-size:13.5px}
  .r-ico{width:30px;height:30px;border-radius:9px}
  .r-ico .ic{width:17px;height:17px}
  .r-lead{width:30px;height:30px}
  .r-act{opacity:0;transition:opacity .14s}
  .row:hover .r-act,.row.selected .r-act{opacity:1}
  .tabbar{display:none}
  .fab{bottom:26px;right:30px;width:52px;height:52px;border-radius:16px}
  .selactions{left:50%;right:auto;bottom:20px;transform:translate(-50%,150%);width:min(600px,calc(100vw - 340px));
    border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow-3);
    border-radius:18px;border:1px solid var(--line);box-shadow:var(--shadow-2);padding:8px 10px;background:var(--surface)}
  .selactions.on{transform:translate(-50%,0)}
  .clipbar{left:auto;right:30px;bottom:92px;width:min(420px,calc(100vw - 340px))}
  .sheet{left:50%;right:auto;bottom:auto;top:50%;width:min(460px,calc(100vw - 60px));max-height:84vh;
    border-radius:22px;transform:translate(-50%,-46%) scale(.97);opacity:0;pointer-events:none;
    transition:.22s var(--ease);padding-bottom:0}
  .sheet.on{transform:translate(-50%,-50%);opacity:1;pointer-events:auto}
  .sheet-handle{display:none}
  .sheet.settings{width:min(620px,calc(100vw - 80px));height:auto;max-height:84vh}
  .sheet.settings .sheet-body{padding-bottom:22px}
  .sheet-head{padding:18px 20px 10px}
  .sheet-body{padding:2px 16px 16px}
  .editor{inset:4vh 6vw;border-radius:20px;overflow:hidden;box-shadow:var(--shadow-2);border:1px solid var(--line)}
  .ed-head{padding:10px 14px}
  .progress{bottom:34px}
  .toaster{bottom:100px}
  .list.selecting .r-ico{display:none}
  .list.selecting .r-check{display:flex}
  .empty{padding:80px 20px}
}
@media (min-width:900px) and (max-width:1100px){
  :root{--sidebar:230px}
  .row{grid-template-columns:34px minmax(0,1fr) 80px 110px 40px}
  .r-col.r-perm{display:none}
  .thead .th-perm{display:none}
}
@media (min-width:900px){
  .list.hide-perm .row{grid-template-columns:34px minmax(0,1fr) 88px 132px 40px}
}
@media (max-width:380px){
  .scroll{padding-left:9px;padding-right:9px}
  .hero{padding:16px 15px 14px}
  .setstore{padding:15px 14px 12px}
  .setstore-value{font-size:21px}
  .hero-value{font-size:22px}
  .r-name{font-size:13.5px}
  .hero-btn{padding:0 10px}
}
@media (prefers-reduced-motion:reduce){
  *{animation-duration:.01ms!important;transition-duration:.01ms!important}
}
/* XZ_PV_THEME_PATCH_V1 · 预览层主题变量（随设置变化，勿删本行标记） */
/* 预览 / 压缩包浏览 / 首次引导浮层的配色全部走这里的变量，浅色与深色各一套 */
:root{
  --pv-bg:#eceef1;
  --pv-bar:rgba(255,255,255,.86);
  --pv-fg:#1f2328;
  --pv-sub:#647082;
  --pv-dim:#78859a;
  --pv-btn:#39424f;
  --pv-chip:rgba(0,0,0,.055);
  --pv-chip-2:rgba(0,0,0,.085);
  --pv-hover:rgba(0,0,0,.06);
  --pv-line:rgba(0,0,0,.12);
  --pv-pre:#2b3441;
  --pv-accent:#1f6feb;
  --pv-accent-bg:rgba(31,111,235,.10);
  --pv-warn:#9a6400;
  --pv-err:#d92d20;   /* 提示/错误文字 */
  --pv-shadow:0 12px 40px rgba(0,0,0,.12);
  --sgm-veil:rgba(233,236,242,.80);
}
html[data-theme="dark"],body[data-theme="dark"],html.dark,body.dark{
  --pv-bg:#0b0d10;
  --pv-bar:rgba(20,22,26,.78);
  --pv-fg:#e6e8eb;
  --pv-sub:#8b97ac;
  --pv-dim:#7f8ca1;
  --pv-btn:#dbe3ef;
  --pv-chip:rgba(255,255,255,.07);
  --pv-chip-2:rgba(255,255,255,.10);
  --pv-hover:rgba(255,255,255,.07);
  --pv-line:rgba(255,255,255,.08);
  --pv-pre:#cdd6e5;
  --pv-accent:#8fc0ff;
  --pv-accent-bg:rgba(90,169,255,.13);
  --pv-warn:#ffcf8a;
  --pv-err:#ff8593;
  --pv-shadow:0 12px 40px rgba(0,0,0,.55);
  --sgm-veil:rgba(6,8,14,.72);
}
@media (prefers-color-scheme:dark){
  html[data-theme="system"],body[data-theme="system"]{
    --pv-bg:#0b0d10;
    --pv-bar:rgba(20,22,26,.78);
    --pv-fg:#e6e8eb;
    --pv-sub:#8b97ac;
    --pv-dim:#7f8ca1;
    --pv-btn:#dbe3ef;
    --pv-chip:rgba(255,255,255,.07);
    --pv-chip-2:rgba(255,255,255,.10);
    --pv-hover:rgba(255,255,255,.07);
    --pv-line:rgba(255,255,255,.08);
    --pv-pre:#cdd6e5;
    --pv-accent:#8fc0ff;
    --pv-accent-bg:rgba(90,169,255,.13);
    --pv-warn:#ffcf8a;
    --pv-err:#ff8593;
    --pv-shadow:0 12px 40px rgba(0,0,0,.55);
    --sgm-veil:rgba(6,8,14,.72);
  }
}
@media (prefers-color-scheme:light){
  html[data-theme="system"],body[data-theme="system"]{
    --pv-bg:#eceef1;
    --pv-bar:rgba(255,255,255,.86);
    --pv-fg:#1f2328;
    --pv-sub:#647082;
    --pv-dim:#78859a;
    --pv-btn:#39424f;
    --pv-chip:rgba(0,0,0,.055);
    --pv-chip-2:rgba(0,0,0,.085);
    --pv-hover:rgba(0,0,0,.06);
    --pv-line:rgba(0,0,0,.12);
    --pv-pre:#2b3441;
    --pv-accent:#1f6feb;
    --pv-accent-bg:rgba(31,111,235,.10);
    --pv-warn:#9a6400;
    --pv-err:#d92d20;
    --pv-shadow:0 12px 40px rgba(0,0,0,.12);
    --sgm-veil:rgba(233,236,242,.80);
  }
}
/* ------ 预览层：底色、文字、按钮统一跟随主题设置 ------ */
.viewer{background:var(--pv-bg);color:var(--pv-fg)}
.v-body img,.v-body video,.v-body canvas{box-shadow:0 0 0 1px var(--pv-line)}
.v-head small{color:var(--pv-sub)}
.v-head button{color:var(--pv-btn)}
.v-head button:hover{background:var(--pv-hover)}
.v-body pre{color:var(--pv-pre)}
.pv-asub{color:var(--pv-sub)}
.pv-disc{color:var(--pv-accent);border-color:var(--pv-line);box-shadow:0 10px 30px -14px rgba(0,0,0,.35)}
.pv-atitle{color:var(--pv-fg)}
.pv-fail-ico{background:var(--pv-chip);color:var(--pv-sub)}
.pv-fail-msg{color:var(--pv-fg)}
.pv-fail-tip{color:var(--pv-sub)}
.pv-btn{color:var(--pv-btn);background:var(--pv-chip);border-color:var(--pv-line)}
.pv-btn.on{background:var(--pv-accent-bg);border-color:var(--pv-accent);color:var(--pv-accent)}
/* ------ 压缩包在线浏览 ------ */
.zip-top{border-bottom-color:var(--pv-line)}
.zip-chip{background:var(--pv-chip);color:var(--pv-sub)}
.zip-chip b{color:var(--pv-fg)}
.zip-up{background:var(--pv-accent-bg);color:var(--pv-accent)}
.zip-up:hover{background:var(--pv-accent-bg)}
.zip-up:active{background:var(--pv-accent-bg);color:var(--pv-fg)}
.zip-crumb{color:var(--pv-sub)}
.zip-crumb[data-zdir]:hover,.zip-crumb[data-zdir]:focus-visible{background:var(--pv-hover);color:var(--pv-fg)}
.zip-crumb.on{color:var(--pv-fg);background:var(--pv-chip-2)}
.zip-crumb:active{background:var(--pv-chip-2)}
.zip-crumb-sep{color:var(--pv-dim)}
.zip-search .ic{color:var(--pv-dim)}
.zip-search input{background:var(--pv-chip);border-color:var(--pv-line);color:var(--pv-fg)}
.zip-search input::placeholder{color:var(--pv-dim)}
.zip-search input:focus{border-color:var(--pv-accent);background:var(--pv-accent-bg)}
.zip-clear{color:var(--pv-sub)}
.zip-row{color:var(--pv-fg)}
.zip-row:active,.zip-row:focus-visible{background:var(--pv-hover)}
.zip-ico{background:var(--pv-chip);color:var(--pv-sub)}
.zip-ico.dir{color:var(--pv-accent);background:var(--pv-accent-bg)}
.zip-ico.zip{color:var(--pv-warn);background:rgba(255,183,77,.13)}
.zip-meta{color:var(--pv-dim)}
.zip-dl{color:var(--pv-sub)}
.zip-dl:active{background:var(--pv-hover);color:var(--pv-fg)}
.zip-lock{color:var(--pv-dim)}
.zip-note{color:var(--pv-dim)}
.zip-empty{color:var(--pv-dim)}
.zip-empty .ic{color:var(--pv-dim)}
.zip-more button{background:var(--pv-chip-2);color:var(--pv-btn)}
.zip-vhead{border-bottom-color:var(--pv-line)}
.zip-back{color:var(--pv-btn)}
.zip-back:active{background:var(--pv-hover)}
.zip-vname small{color:var(--pv-dim)}
.zip-pre{color:var(--pv-pre)}
.zip-missing{color:var(--pv-sub)}
.zip-missing .ic{color:var(--pv-dim)}
.zip-btn{background:var(--pv-accent-bg);color:var(--pv-accent)}
.zip-spin{border-color:var(--pv-line);border-top-color:var(--pv-accent)}
/* ------ 首次引导浮层遮罩 ------ */
.sgm{background:var(--sgm-veil)}
</style>
</head>
<body>
<svg class="sprite" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
  <symbol id="i-logo" viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.1c.6 0 1.2.3 1.6.8l1 1.2h6.3A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-12A2.5 2.5 0 0 1 3 16.5v-9Z"/></symbol>
  <symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.1c.6 0 1.2.3 1.6.8l1 1.2h6.3A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-12A2.5 2.5 0 0 1 3 16.5v-9Z"/></symbol>
  <symbol id="i-file" viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5"/></symbol>
  <symbol id="i-image" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="m20 16-5-5-5 5-2.5-2.5L4 17"/></symbol>
  <symbol id="i-video" viewBox="0 0 24 24"><rect x="3" y="5" width="13" height="14" rx="2.5"/><path d="m16 10 5-3v10l-5-3"/></symbol>
  <symbol id="i-audio" viewBox="0 0 24 24"><path d="M9 18V6l10-2v12"/><circle cx="6" cy="18" r="2.6"/><circle cx="16" cy="16" r="2.6"/></symbol>
  <symbol id="i-doc" viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M9 13h6M9 17h4"/></symbol>
  <symbol id="i-archive" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="4" rx="1.4"/><path d="M5 8v10.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V8"/><path d="M10 12h4"/></symbol>
  <symbol id="i-text" viewBox="0 0 24 24"><path d="M4 6h16M4 12h10M4 18h14"/></symbol>
  <symbol id="i-code" viewBox="0 0 24 24"><path d="m9 8-4 4 4 4M15 8l4 4-4 4"/></symbol>
  <symbol id="i-back" viewBox="0 0 24 24"><path d="m14 6-6 6 6 6"/></symbol>
  <symbol id="i-chevron" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></symbol>
  <symbol id="i-chevrond" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/></symbol>
  <symbol id="i-more" viewBox="0 0 24 24"><circle cx="5.5" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="18.5" cy="12" r="1.4" fill="currentColor" stroke="none"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
  <symbol id="i-upload" viewBox="0 0 24 24"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></symbol>
  <symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4v12m0 0-4.5-4.5M12 16l4.5-4.5"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><path d="M6.5 7 7.5 20h9L17.5 7"/><path d="M10 11v5M14 11v5"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3"/></symbol>
  <symbol id="i-cut" viewBox="0 0 24 24"><circle cx="6" cy="18" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8 16 18 4M16 16 6 4"/></symbol>
  <symbol id="i-paste" viewBox="0 0 24 24"><path d="M9 4h6v3H9z"/><path d="M15 5h2a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/><path d="M9 12h6M9 16h4"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4l10-10a2.4 2.4 0 0 0-3.4-3.4L4.6 16.6 4 20Z"/><path d="m14.5 6.5 3 3"/></symbol>
  <symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a4 4 0 0 0 5.7 0l2.6-2.6A4 4 0 0 0 12.6 4.7L11 6.3"/><path d="M14 11a4 4 0 0 0-5.7 0L5.7 13.6a4 4 0 0 0 5.7 5.7l1.5-1.6"/></symbol>
  <symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><circle cx="12" cy="8" r=".9" fill="currentColor" stroke="none"/></symbol>
  <symbol id="i-close" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7"/></symbol>
  <symbol id="i-ckbox" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="4"/><path d="m8.5 12 2.5 2.5 4.5-5"/></symbol>
  <symbol id="i-sort" viewBox="0 0 24 24"><path d="M7 4v16m0 0-3-3m3 3 3-3"/><path d="M14 8h6M14 13h4M14 18h2"/></symbol>
  <symbol id="i-grid" viewBox="0 0 24 24"><rect x="4" y="4" width="7" height="7" rx="2"/><rect x="13" y="4" width="7" height="7" rx="2"/><rect x="4" y="13" width="7" height="7" rx="2"/><rect x="13" y="13" width="7" height="7" rx="2"/></symbol>
  <symbol id="i-list" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
  <symbol id="i-star" viewBox="0 0 24 24"><path d="m12 4 2.4 5.2 5.6.7-4.1 3.9 1.1 5.6-5-2.9-5 2.9 1.1-5.6L4 9.9l5.6-.7L12 4Z"/></symbol>
  <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></symbol>
  <symbol id="i-settings" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1v.2a2 2 0 0 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H4a2 2 0 0 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H10a1.6 1.6 0 0 0 1-1.5V4a2 2 0 0 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V10a1.6 1.6 0 0 0 1.5 1H22a2 2 0 0 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M15 4h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-2"/><path d="M10 8 6 12l4 4M6 12h9"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3.5 19 6v6c0 4.2-2.9 7.4-7 8.5-4.1-1.1-7-4.3-7-8.5V6l7-2.5Z"/><path d="m9 12 2 2 4-4"/></symbol>
  <symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.2 2.3 3.4 5.3 3.4 8.5s-1.2 6.2-3.4 8.5c-2.2-2.3-3.4-5.3-3.4-8.5S9.8 5.8 12 3.5Z"/></symbol>
  <symbol id="i-server" viewBox="0 0 24 24"><rect x="3.5" y="4" width="17" height="6.5" rx="2"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="2"/><path d="M7 7.2h.01M7 16.8h.01"/></symbol>
  <symbol id="i-github" viewBox="0 0 24 24"><path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.3 4.3 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12 12 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.3 4.3 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"/></symbol>
  <symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-13.7-4.7L4 8.5"/><path d="M4 4v4.5h4.5"/><path d="M4 13a8 8 0 0 0 13.7 4.7L20 15.5"/><path d="M20 20v-4.5h-4.5"/></symbol>
  <symbol id="i-undo" viewBox="0 0 24 24"><path d="M4.5 9.5h8.8a5.2 5.2 0 0 1 0 10.4H9"/><path d="m8.5 5.5-4 4 4 4"/></symbol>
  <symbol id="i-redo" viewBox="0 0 24 24"><path d="M19.5 9.5h-8.8a5.2 5.2 0 0 0 0 10.4H15"/><path d="m15.5 5.5 4 4-4 4"/></symbol>
  <symbol id="i-folderplus" viewBox="0 0 24 24"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.1c.6 0 1.2.3 1.6.8l1 1.2h6.3A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-12A2.5 2.5 0 0 1 3 16.5v-9Z"/><path d="M12 11v5M9.5 13.5h5"/></symbol>
  <symbol id="i-fileplus" viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5"/><path d="M12 12v5M9.5 14.5h5"/></symbol>
  <symbol id="i-zip" viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="3"/><path d="M12 3v3M12 9v3M12 15v3"/></symbol>
  <symbol id="i-unzip" viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="3"/><path d="M10 8h4M10 12h4M10 16h4"/></symbol>
  <symbol id="i-eye" viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><rect x="4.5" y="10" width="15" height="10" rx="2.5"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/></symbol>
  <symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8.5" r="3.6"/><path d="M5 20c.6-3.6 3.4-5.6 7-5.6s6.4 2 7 5.6"/></symbol>
  <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.2 5.2l1.4 1.4M17.4 17.4l1.4 1.4M18.8 5.2l-1.4 1.4M6.6 17.4l-1.4 1.4"/></symbol>
  <symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/></symbol>
  <symbol id="i-selectall" viewBox="0 0 24 24"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="m8.5 12 2.4 2.4 4.6-4.8"/></symbol>
  <symbol id="i-invert" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="4"/><path d="M12 4v16" /><path d="M15 9.5 18 12l-3 2.5"/></symbol>
  <symbol id="i-external" viewBox="0 0 24 24"><path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/></symbol>
  <symbol id="i-cloud" viewBox="0 0 24 24"><path d="M7 18a4 4 0 0 1-.6-8A5.5 5.5 0 0 1 17 9.4 3.8 3.8 0 0 1 16.8 18H7Z"/><path d="M12 14v-3M10.6 12.4 12 11l1.4 1.4"/></symbol>
  <symbol id="i-spark" viewBox="0 0 24 24"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M18 6l-2.5 2.5M8.5 15.5 6 18"/></symbol>
  <symbol id="i-sortdir" viewBox="0 0 24 24"><path d="M7.5 4v15.5M7.5 19.5 4.2 16.2M7.5 19.5l3.3-3.3"/><path d="M16.5 20V4.5M16.5 4.5l-3.3 3.3M16.5 4.5l3.3 3.3"/></symbol>
  <symbol id="i-drive" viewBox="0 0 24 24"><path d="M4.5 15 8 6h8l3.5 9"/><rect x="3" y="15" width="18" height="5" rx="2"/><path d="M7 17.5h.01"/></symbol>
</svg>

<div class="app" id="app">
  <!-- ================= 桌面侧边栏 ================= -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark"><svg class="ic ic-lg"><use href="#i-logo"></use></svg></div>
      <div>
        <h1><?php echo $HTML_TITLE; ?></h1>
        <p data-i18n="brand_sub">单文件文件管理器</p>
      </div>
    </div>
    <div class="nav-label" data-i18n="files">文件</div>
    <button class="nav-item active" data-view="files">
      <svg class="ic"><use href="#i-folder"></use></svg><span data-i18n="all_files">全部文件</span>
    </button>
    <button class="nav-item" data-view="recent">
      <svg class="ic"><use href="#i-clock"></use></svg><span data-i18n="recent">最近</span>
    </button>
    <div class="side-foot">
      <span><?php echo XIAZZI_VERSION; ?></span>
      <button class="linkbtn" id="btnSideSettings" data-i18n="settings">设置</button>
    </div>
  </aside>

  <!-- ================= 主区 ================= -->
  <main class="main">
    <header class="topbar" id="topbar">
      <div class="tb-lead">
        <button class="iconbtn" id="btnBack" hidden aria-label="back"><svg class="ic"><use href="#i-back"></use></svg></button>
      </div>
      <div class="tb-tx">
        <div class="tb-title" id="tbTitle" data-i18n="all_files">全部文件</div>
        <div class="tb-sub" id="tbSub">—</div>
      </div>
      <div class="tb-tools" id="tbTools">
        <button class="iconbtn" id="btnSelect" aria-label="select"><svg class="ic"><use href="#i-ckbox"></use></svg></button>
        <button class="iconbtn" id="btnSearch" aria-label="search"><svg class="ic"><use href="#i-search"></use></svg></button>
        <button class="iconbtn" id="btnMore" aria-label="more"><svg class="ic"><use href="#i-more"></use></svg></button>
      </div>
      <div class="searchbar" id="searchBar">
        <button class="iconbtn" id="btnSearchClose" aria-label="close"><svg class="ic"><use href="#i-back"></use></svg></button>
        <div class="field">
          <svg class="ic ic-sm"><use href="#i-search"></use></svg>
          <input id="searchInput" type="search" enterkeyhint="search" autocomplete="off" data-i18n-ph="search_ph" placeholder="搜索">
          <button class="iconbtn" id="btnSearchClear" style="width:26px;height:26px" aria-label="clear"><svg class="ic ic-sm"><use href="#i-close"></use></svg></button>
        </div>
      </div>
    </header>

    <div class="selbar" id="selBar">
      <div class="cnt"><span data-i18n="selected">已选</span> <span id="selCount">0</span> <span data-i18n="items">项</span></div>
      <div class="acts">
        <button id="btnSelAll" data-i18n="select_all">全选</button>
        <button id="btnSelInvert" data-i18n="invert">反选</button>
        <button id="btnSelDone" class="plain" data-i18n="cancel">取消</button>
      </div>
    </div>

    <div class="scroll" id="scroll">
      <div class="inner">
        <div class="chips" id="chips"></div>

        <div class="listhead">
          <div class="lh-left">
            <div class="lh-stats" id="listStats" hidden></div>
          </div>
          <div class="lh-right">
            <button class="sortbtn" id="btnSort">
              <svg class="ic ic-sm"><use href="#i-sort"></use></svg><span id="sortLabel">名称</span>
            </button>
            <div class="seg">
              <button id="btnViewList" class="on" aria-label="list"><svg class="ic ic-sm"><use href="#i-list"></use></svg></button>
              <button id="btnViewGrid" aria-label="grid"><svg class="ic ic-sm"><use href="#i-grid"></use></svg></button>
            </div>
          </div>
        </div>

        <div class="thead" id="thead">
          <div class="th-name"><button id="thName"><span data-i18n="name">名称</span></button></div>
          <button class="th-size" id="thSize"><span data-i18n="size">大小</span></button>
          <button class="th-time" id="thTime"><span data-i18n="modified">修改时间</span></button>
          <button class="th-perm" id="thPerm"><span data-i18n="perm">权限</span></button>
          <div class="th-act"></div>
        </div>

        <div class="list" id="list"></div>
        <div class="empty" id="empty">
          <div class="eico"><svg class="ic" style="width:30px;height:30px"><use href="#i-folder"></use></svg></div>
          <h3 id="emptyTitle" data-i18n="empty">这里还空着</h3>
          <p id="emptySub" data-i18n="empty_sub">点击右下角按钮上传或新建</p>
          <button class="btn btn-primary" id="emptyBtn" style="width:auto;padding:0 20px;margin-top:16px;height:40px">
            <svg class="ic ic-sm"><use href="#i-upload"></use></svg><span data-i18n="upload">上传文件</span>
          </button>
        </div>
      </div>
    </div>

    <div class="clipbar" id="clipBar">
      <svg class="ic ic-sm"><use href="#i-cut"></use></svg>
      <span class="txt" id="clipText"></span>
      <button id="btnPaste" data-i18n="paste">粘贴</button>
      <button class="x" id="btnClipClear" aria-label="clear"><svg class="ic ic-sm"><use href="#i-close"></use></svg></button>
    </div>

    <div class="selactions" id="selActions">
      <button data-sel="copy"><svg class="ic"><use href="#i-copy"></use></svg><span data-i18n="copy">复制</span></button>
      <button data-sel="cut"><svg class="ic"><use href="#i-cut"></use></svg><span data-i18n="cut">剪切</span></button>
      <button data-sel="compress"><svg class="ic"><use href="#i-zip"></use></svg><span data-i18n="compress">压缩</span></button>
      <button data-sel="link"><svg class="ic"><use href="#i-link"></use></svg><span data-i18n="link">直链</span></button>
      <button data-sel="stat"><svg class="ic"><use href="#i-info"></use></svg><span>统计</span></button>
      <button data-sel="delete" class="danger"><svg class="ic"><use href="#i-trash"></use></svg><span data-i18n="delete">删除</span></button>
      <button data-sel="more"><svg class="ic"><use href="#i-more"></use></svg><span data-i18n="more">更多</span></button>
    </div>

    <button class="fab" id="fab" aria-label="new" aria-haspopup="dialog"><svg class="ic"><use href="#i-plus"></use></svg></button>

    <nav class="tabbar" id="tabbar">
      <button class="tab on" data-view="files"><svg class="ic"><use href="#i-folder"></use></svg><span data-i18n="files">文件</span></button>
      <button class="tab" data-view="recent"><svg class="ic"><use href="#i-clock"></use></svg><span data-i18n="recent">最近</span></button>
      <button class="tab" data-view="settings"><svg class="ic"><use href="#i-settings"></use></svg><span data-i18n="settings">设置</span></button>
    </nav>
  </main>
</div>

<!-- ================= 弹层 ================= -->
<div class="backdrop" id="backdrop"></div>

<div class="sheet" id="sheet" role="dialog" aria-modal="true">
  <div class="sheet-handle"></div>
  <div class="sheet-head">
    <div class="st"><strong id="sheetTitle"></strong><span id="sheetHint"></span></div>
    <button class="iconbtn" id="sheetClose" aria-label="close"><svg class="ic"><use href="#i-close"></use></svg></button>
  </div>
  <div class="sheet-body" id="sheetBody"></div>
</div>

<div class="sheet settings" id="settingsSheet" role="dialog" aria-modal="true">
  <div class="sheet-handle"></div>
  <div class="sheet-head">
    <div class="st"><strong data-i18n="settings">设置</strong><span id="settingsHint"></span></div>
    <button class="iconbtn" id="settingsClose" aria-label="close"><svg class="ic"><use href="#i-close"></use></svg></button>
  </div>
  <div class="stabs" id="settingsTabs">
    <button data-stab="general" class="on"><svg class="ic"><use href="#i-settings"></use></svg><span data-i18n="settings_general">通用</span></button>
    <button data-stab="security"><svg class="ic"><use href="#i-shield"></use></svg><span data-i18n="settings_security">安全</span></button>
    <button data-stab="env"><svg class="ic"><use href="#i-server"></use></svg><span data-i18n="settings_env">环境</span></button>
    <button data-stab="about"><svg class="ic"><use href="#i-info"></use></svg><span data-i18n="settings_about">关于</span></button>
  </div>
  <div class="sheet-body" id="settingsBody"></div>
</div>

<div class="dialog" id="dialog" role="dialog" aria-modal="true">
  <h3 id="dlgTitle">标题</h3>
  <p id="dlgText">说明</p>
  <input class="field" id="dlgInput" hidden autocomplete="off" spellcheck="false">
  <div id="dlgExtra"></div>
  <div class="hint" id="dlgHint"></div>
  <div class="dialog-actions">
    <button class="btn btn-ghost" id="dlgCancel" data-i18n="cancel">取消</button>
    <button class="btn btn-primary" id="dlgOk" data-i18n="ok">确定</button>
  </div>
</div>

<!-- 压缩对话框 -->
<div class="cmpdlg" id="cmpDlg" role="dialog" aria-modal="true" aria-labelledby="cmpTitle">
  <div class="cmpcard">
    <div class="cmphead">
      <h3 id="cmpTitle" data-i18n="cmp_title">创建压缩文件</h3>
      <p><svg class="ic"><use href="#i-folder"></use></svg><span id="cmpSub"></span></p>
    </div>
    <div class="cmpbody" id="cmpBody"></div>
    <div class="cmpfoot">
      <button type="button" class="cmpbtn" id="cmpCancel" data-i18n="cancel">取消</button>
      <button type="button" class="cmpbtn primary" id="cmpGo" data-i18n="cmp_create">创建</button>
    </div>
  </div>
</div>

<!-- 编辑器 -->
<div class="editor" id="editor" role="dialog" aria-modal="true">
  <div class="ed-head">
    <button class="iconbtn" id="edClose" aria-label="close"><svg class="ic"><use href="#i-back"></use></svg></button>
    <div class="ed-tx"><b id="edName">file.txt</b><small id="edPath">—</small></div>
    <div class="ed-tools">
      <button class="ed-save" id="edSave" disabled><svg class="ic ic-sm"><use href="#i-check"></use></svg><span data-i18n="save">保存</span></button>
    </div>
  </div>
  <div class="ed-sub">
    <div class="segsm" id="edModes">
      <button data-mode="normal" data-i18n="editor_normal">普通</button>
      <button data-mode="advanced" data-i18n="editor_adv">高级</button>
    </div>
    <div class="sp"></div>
    <button class="iconbtn" id="edFind" style="width:30px;height:30px" aria-label="find"><svg class="ic ic-sm"><use href="#i-search"></use></svg></button>
    <span class="ed-perf" id="edPerf"></span>
    <span class="tiny" id="edInfo">—</span>
  </div>
  <div class="ed-toolrow" id="edToolRow">
    <button data-tool="undo" id="btnUndo" title="撤销"><svg class="ic ic-sm"><use href="#i-undo"></use></svg><span data-i18n="undo">撤销</span></button>
    <button data-tool="redo" id="btnRedo" title="重做"><svg class="ic ic-sm"><use href="#i-redo"></use></svg><span data-i18n="redo">重做</span></button>
    <span class="tsep"></span>
    <button data-tool="backup" id="btnBackup"><svg class="ic ic-sm"><use href="#i-doc"></use></svg><span data-i18n="backup">备份</span></button>
    <button data-tool="goto" id="btnGoto"><svg class="ic ic-sm"><use href="#i-chevron"></use></svg><span data-i18n="goto_line">跳转行</span></button>
    <button data-tool="wrap" id="btnWrap"><svg class="ic ic-sm"><use href="#i-text"></use></svg><span data-i18n="wrap">自动换行</span></button>
    <button data-tool="ln" id="btnLn"><svg class="ic ic-sm"><use href="#i-list"></use></svg><span data-i18n="line_numbers">行号</span></button>
    <button data-tool="hl" id="btnHl"><svg class="ic ic-sm"><use href="#i-code"></use></svg><span data-i18n="highlight">语法高亮</span></button>
    <span class="tsep"></span>
    <button data-tool="enc" id="btnEnc"><svg class="ic ic-sm"><use href="#i-globe"></use></svg><span id="encLabel">UTF-8</span></button>
  </div>
  <!-- 编码面板：内联在编辑器内，不离开当前页；普通 / 高级编辑器通用 -->
  <div class="ed-enc" id="encPop" role="dialog" aria-label="encoding">
    <div class="ed-enc-head">
      <b data-i18n="file_encoding">文件编码</b>
      <span class="cur" id="encCur">UTF-8</span>
      <button type="button" class="ed-enc-x" id="encX" aria-label="close"><svg class="ic ic-sm"><use href="#i-close"></use></svg></button>
    </div>
    <div class="ed-enc-tabs" id="encTabs">
      <button type="button" data-tab="save" class="on" data-i18n="enc_tab_save">保存编码</button>
      <button type="button" data-tab="read" data-i18n="enc_tab_read">读取编码</button>
    </div>
    <div class="ed-enc-list" id="encList"></div>
    <div class="ed-enc-note" id="encNote"></div>
    <div class="ed-enc-foot"><button type="button" class="ed-enc-go" id="encApply" data-i18n="enc_convert_save">转换并保存</button></div>
  </div>
  <div class="findbar" id="findBar">
    <input id="findInput" data-i18n-ph="find_ph" placeholder="查找">
    <input id="replaceInput" data-i18n-ph="replace_ph" placeholder="替换为">
    <button id="findPrev">↑</button>
    <button id="findNext">↓</button>
    <button id="replaceOne" data-i18n="replace">替换</button>
    <button id="replaceAll" data-i18n="replace_all">全部替换</button>
    <span class="cnt" id="findCount"></span>
    <button id="findClose" aria-label="close"><svg class="ic ic-sm"><use href="#i-close"></use></svg></button>
  </div>
  <div class="ed-body">
    <div class="ed-pane on" id="paneNormal">
      <textarea class="ed-plain" id="edPlain" spellcheck="false" wrap="off" autocapitalize="off" autocomplete="off"></textarea>
    </div>
    <div class="ed-pane" id="paneAdv">
      <div class="adv-wrap" id="advWrap">
        <div class="gutter" id="gutter" aria-hidden="true"><div class="gut-in" id="gutIn"></div></div>
        <div class="adv-scroll" id="advScroll">
          <div class="adv-inner">
            <pre class="hl" id="hl" aria-hidden="true"></pre>
            <textarea class="adv-ta" id="advTa" spellcheck="false" wrap="off" autocapitalize="off" autocomplete="off"></textarea>
          </div>
        </div>
      </div>
    </div>
    <div class="ed-mask" id="edMask"><div class="ed-spin"></div><span id="edMaskText">Loading…</span></div>
  </div>
  <div class="ed-status">
    <span id="edCursor">行 1，列 1</span>
    <span class="sp"></span>
    <span id="edChars">0 字符</span>
    <button type="button" class="ed-encchip" id="edEncChip" title="encoding">UTF-8</button>
    <span id="edType">TEXT</span>
  </div>
</div>

<!-- 预览 -->
<div class="viewer" id="viewer" role="dialog" aria-modal="true">
  <div class="v-head">
    <div class="vt"><b id="vName"></b><small id="vMeta"></small></div>
    <button id="vLink" aria-label="link"><svg class="ic"><use href="#i-link"></use></svg></button>
    <button id="vEdit" aria-label="edit"><svg class="ic"><use href="#i-edit"></use></svg></button>
    <button id="vDownload" aria-label="download"><svg class="ic"><use href="#i-download"></use></svg></button>
    <button id="vClose" aria-label="close"><svg class="ic"><use href="#i-close"></use></svg></button>
  </div>
  <div class="v-body" id="vBody"></div>
</div>

<!-- 进度 -->
<div class="progress" id="progress">
  <div class="pt"><svg class="ic ic-sm"><use href="#i-upload"></use></svg><span id="progressText">上传中</span><b id="progressPct">0%</b></div>
  <div class="pb"><i id="progressBar"></i></div>
</div>

<div class="toaster" id="toaster"></div>

<input type="file" id="fileInput" multiple hidden>
<input type="file" id="folderInput" webkitdirectory directory multiple hidden>

<div class="sgm" id="setupGuide" hidden>
  <div class="sgm-card" role="dialog" aria-modal="true" aria-labelledby="sgmTitle">
    <div class="sgm-head">
      <span class="sgm-mark"><svg class="ic"><use href="#i-shield"></use></svg></span>
      <div class="sgm-ht"><b id="sgmTitle">完成安全设置</b><span id="sgmSub">首次使用需设置专属账号密码</span></div>
      <button type="button" class="sgm-x" id="sgmExit" aria-label="退出登录"><svg class="ic"><use href="#i-logout"></use></svg></button>
    </div>
    <div class="sgm-body" id="sgmBody"></div>
  </div>
</div>

<script>window.__BOOT__ = <?php echo $BOOT_JSON; ?>;</script>
<script>window.__I18N__ = <?php echo $I18N_JSON; ?>;</script>
<script>
(function ()  {
  'use strict';

  /* ============================================================
     0. 状态与工具
     ============================================================ */
  var BOOT = window.__BOOT__ || {};
  var DICTS = window.__I18N__ || {};
  var S = {
    lang: BOOT.lang || 'zh-CN',
    settings: BOOT.settings || {},
    view: 'files',
    path: '',
    items: [],
    kind: 'all',
    sort: 'name',
    dir: 1,
    viewMode: localStorage.getItem('xiazzi.view') || 'list',
    selecting: false,
    sel: {},
    selCount: 0,
    clip: null,
    searchMode: false,
    searchQ: '',
    loading: false,
    storage: BOOT.storage || null,
    dirStats: null,
    lastTap: 0,
    editor: null
  };

  function T(key)  {
    var d = DICTS[S.lang] || DICTS['zh-CN'] || {};
    if (d[key] !== undefined) return d[key];
    var f = DICTS['zh-CN'] || {};
    return f[key] !== undefined ? f[key] : key;
  }
  function esc(s)  {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function icon(name,  cls)  {
    return '<svg class="ic ' + (cls || '') + '"><use href="#i-' + name + '"></use></svg>';
  }
  function $(id) { return document.getElementById(id); }
  function el(sel,  root)  { return (root || document).querySelector(sel); }
  function all(sel,  root)  { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function on(target,  type,  fn,  opts)  { if (target) target.addEventListener(type, fn, opts || false); }
  function fmtSize(bytes)  {
    bytes = Number(bytes) || 0;
    if (!bytes) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0; var v = bytes;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
  }
  function fmtDate(ts)  {
    if (!ts) return '—';
    var d = new Date(ts * 1000);
    var now = new Date();
    var pad = function (n)  { return n < 10 ? '0' + n : '' + n; };
    var hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
    var dayPrefix = { 'en': '', 'zh-TW': '今天 ', 'zh-CN': '今天 ', 'ja': '今日 ', 'ko': '오늘 ', 'es': 'Hoy ' };
    if (d.toDateString() === now.toDateString()) return (dayPrefix[S.lang] !== undefined ? dayPrefix[S.lang] : '今天 ') + hm;
    if (d.getFullYear() === now.getFullYear()) return (d.getMonth() + 1) + '/' + d.getDate() + ' ' + hm;
    return d.getFullYear() + '/' + pad(d.getMonth() + 1) + '/' + pad(d.getDate());
  }
  function kindClass(kind)  {
    var map = { folder: 'folder', image: 'image', video: 'video', audio: 'audio', doc: 'doc', archive: 'archive', text: 'text', file: 'file' };
    return map[kind] || 'file';
  }
  function kindIcon(kind)  {
    var map = { folder: 'folder', image: 'image', video: 'video', audio: 'audio', doc: 'doc', archive: 'archive', text: 'text', file: 'file' };
    return map[kind] || 'file';
  }

  /* ---------- 文件类型识别（详情面板 / 操作面板使用） ---------- */
  var TYPE_LABELS = {
    'zh-CN': {
      folder: '文件夹', file: '文件', image: '图片', video: '视频', audio: '音频', archive: '压缩包',
      php: 'PHP 文本', web: '网页文件', code: '代码文件', text: '文本文件', word: 'Word 文档',
      pdf: 'PDF 文档', sheet: '表格', slide: '演示文稿', font: '字体文件', database: '数据库',
      disk: '磁盘镜像', exec: '可执行文件', config: '配置文件', data: '数据文件', other: '其他文件'
    },
    'zh-TW': {
      folder: '資料夾', file: '檔案', image: '圖片', video: '影片', audio: '音訊', archive: '壓縮檔',
      php: 'PHP 文字檔', web: '網頁檔', code: '程式碼', text: '文字檔', word: 'Word 文件',
      pdf: 'PDF 文件', sheet: '試算表', slide: '簡報', font: '字型檔', database: '資料庫',
      disk: '磁碟映像', exec: '執行檔', config: '設定檔', data: '資料檔', other: '其他檔案'
    },
    en: {
      folder: 'Folder', file: 'File', image: 'Image', video: 'Video', audio: 'Audio', archive: 'Archive',
      php: 'PHP text', web: 'Web page', code: 'Code', text: 'Text', word: 'Word document',
      pdf: 'PDF document', sheet: 'Spreadsheet', slide: 'Presentation', font: 'Font', database: 'Database',
      disk: 'Disk image', exec: 'Executable', config: 'Config', data: 'Data', other: 'Other file'
    },
    ja: {
      folder: 'フォルダ', file: 'ファイル', image: '画像', video: '動画', audio: '音声', archive: '圧縮ファイル',
      php: 'PHP テキスト', web: 'Web ページ', code: 'コード', text: 'テキスト', word: 'Word 文書',
      pdf: 'PDF 文書', sheet: '表計算', slide: 'プレゼン', font: 'フォント', database: 'データベース',
      disk: 'ディスクイメージ', exec: '実行ファイル', config: '設定ファイル', data: 'データ', other: 'その他'
    },
    ko: {
      folder: '폴더', file: '파일', image: '이미지', video: '동영상', audio: '오디오', archive: '압축 파일',
      php: 'PHP 텍스트', web: '웹 페이지', code: '코드', text: '텍스트', word: 'Word 문서',
      pdf: 'PDF 문서', sheet: '스프레드시트', slide: '프레젠테이션', font: '글꼴', database: '데이터베이스',
      disk: '디스크 이미지', exec: '실행 파일', config: '설정 파일', data: '데이터', other: '기타 파일'
    },
    es: {
      folder: 'Carpeta', file: 'Archivo', image: 'Imagen', video: 'Vídeo', audio: 'Audio', archive: 'Comprimido',
      php: 'Texto PHP', web: 'Página web', code: 'Código', text: 'Texto', word: 'Documento Word',
      pdf: 'Documento PDF', sheet: 'Hoja de cálculo', slide: 'Presentación', font: 'Fuente', database: 'Base de datos',
      disk: 'Imagen de disco', exec: 'Ejecutable', config: 'Configuración', data: 'Datos', other: 'Otro archivo'
    }
  };
  var TYPE_GROUPS = [
    ['php', 'php php3 php4 php5 php7 php8 phtml phps phpt inc'],
    ['archive', 'zip rar 7z tar gz tgz tar.gz bz2 tbz tbz2 xz txz zst lz lzma cab arj lzh ace jar war'],
    ['font', 'ttf ttc otf woff woff2 eot fon fnt pfb pfm'],
    ['database', 'db sqlite sqlite3 sdf mdb accdb dbf frm myd myi ibd ldf mdf'],
    ['disk', 'iso img dmg vhd vhdx vmdk vdi qcow2 cue nrg toast bin'],
    ['exec', 'exe msi apk ipa deb rpm appimage app com scr pkg run'],
    ['pdf', 'pdf'],
    ['word', 'doc docx odt rtf pages wps wpd'],
    ['sheet', 'xls xlsx xlsm xlsb csv tsv ods numbers et'],
    ['slide', 'ppt pptx pps ppsx odp key dps'],
    ['web', 'html htm xhtml shtml mhtml mht vue svelte astro'],
    ['code', 'js mjs cjs jsx ts tsx css scss sass less styl py pyw rb go rs java kt kts swift c h cc cpp cxx hpp cs m mm sh bash zsh fish bat cmd ps1 lua pl pm r dart scala clj ex exs erl hrl hs sql vb asm s sol zig nim v jl groovy gradle'],
    ['config', 'ini conf cfg config env yaml yml toml properties lock htaccess gitignore gitattributes editorconfig user.ini plist reg service desktop'],
    ['data', 'json jsonl ndjson geojson xml'],
    ['text', 'txt text log md markdown mdown rst nfo readme license changelog authors notice tex']
  ];
  var TYPE_BY_NAME = {
    dockerfile: 'code', makefile: 'code', rakefile: 'code', gemfile: 'code', procfile: 'code',
    readme: 'text', license: 'text', licence: 'text', changelog: 'text', authors: 'text', notice: 'text'
  };
  var TYPE_BY_DOTNAME = {
    '.htaccess': 'config', '.htpasswd': 'config', '.env': 'config', '.gitignore': 'config',
    '.gitattributes': 'config', '.editorconfig': 'config', '.user.ini': 'config'
  };
  function typeKeyOf(item)  {
    if (!item) return 'other';
    if (item.dir) return 'folder';
    var name = String(item.name || '').toLowerCase();
    if (TYPE_BY_DOTNAME[name]) return TYPE_BY_DOTNAME[name];
    var mk = mediaKindOf(name);
    if (mk) return mk;
    var ext = String(item.ext || extOfName(name)).toLowerCase();
    if (!ext) return TYPE_BY_NAME[name] || 'other';
    for (var i = 0; i < TYPE_GROUPS.length; i++) {
      if ((' ' + TYPE_GROUPS[i][1] + ' ').indexOf(' ' + ext + ' ') !== -1) return TYPE_GROUPS[i][0];
    }
    return 'other';
  }
  function typeLabels()  {
    return TYPE_LABELS[S.lang] || TYPE_LABELS['zh-CN'] || {};
  }
  /* 可编辑文本类文档按扩展名给出具体名称：PHP 文本 / HTML 文本 / TXT 文本 / CSS 样式表 … */
  var EXT_KIND = (function ()  {
    var map = {};
    function add(kind, list)  {
      var a = list.split(' ');
      for (var i = 0; i < a.length; i++) { if (a[i]) map[a[i]] = kind; }
    }
    add('php', 'php php3 php4 php5 php7 php8 phtml phps phpt inc');
    add('text', 'txt text log nfo rst tex');
    add('markdown', 'md markdown mdown');
    add('web', 'html htm xhtml shtml mhtml mht');
    add('tpl', 'vue svelte astro');
    add('style', 'css scss sass less styl');
    add('script', 'js mjs cjs jsx ts tsx py pyw rb go rs java kt kts swift c h cc cpp cxx hpp cs m mm sh bash zsh fish bat cmd ps1 lua pl pm r dart scala clj ex exs erl hrl hs sql vb asm s sol zig nim v jl groovy gradle');
    add('data', 'json jsonl ndjson geojson xml csv tsv');
    add('config', 'ini conf cfg config env yaml yml toml properties lock htaccess gitignore gitattributes editorconfig plist reg service desktop');
    return map;
  })();
  var EXT_DISPLAY = {
    md: 'Markdown', markdown: 'Markdown', mdown: 'Markdown', yml: 'YAML', yaml: 'YAML', txt: 'TXT',
    htaccess: 'Apache', gitignore: '.gitignore', gitattributes: '.gitattributes', editorconfig: '.editorconfig',
    js: 'JS', mjs: 'JS', cjs: 'JS', ts: 'TS', jsx: 'JSX', tsx: 'TSX', h: 'C', hpp: 'C++', cxx: 'C++',
    py: 'Python', pyw: 'Python', rb: 'Ruby', sh: 'Shell', bash: 'Bash', ps1: 'PowerShell', sql: 'SQL',
    ini: 'INI', conf: 'CONF', cfg: 'CFG', env: 'ENV', text: 'TXT', csv: 'CSV', tsv: 'TSV'
  };
  var KIND_WORD = {
    'zh-CN': { text: '文本', markdown: '文档', web: '文本', tpl: '模板', style: '样式表', script: '脚本', data: '数据', config: '配置文件', php: '文本' },
    'zh-TW': { text: '文字檔', markdown: '文件', web: '文字檔', tpl: '範本', style: '樣式表', script: '指令碼', data: '資料', config: '設定檔', php: '文字檔' },
    en: { text: 'text', markdown: 'document', web: 'text', tpl: 'template', style: 'stylesheet', script: 'script', data: 'data', config: 'config', php: 'text' },
    ja: { text: 'テキスト', markdown: '文書', web: 'テキスト', tpl: 'テンプレート', style: 'スタイルシート', script: 'スクリプト', data: 'データ', config: '設定', php: 'テキスト' },
    ko: { text: '텍스트', markdown: '문서', web: '텍스트', tpl: '템플릿', style: '스타일시트', script: '스크립트', data: '데이터', config: '설정', php: '텍스트' },
    es: { text: 'texto', markdown: 'documento', web: 'texto', tpl: 'plantilla', style: 'hoja de estilo', script: 'script', data: 'datos', config: 'configuración', php: 'texto' }
  };
  function textTypeLabel(ext)  {
    ext = String(ext || '').toLowerCase();
    if (!ext) return '';
    var kind = EXT_KIND[ext];
    if (!kind) {
      if (!isEditable(ext)) return '';
      kind = 'text';
    }
    var W = KIND_WORD[S.lang] || KIND_WORD['zh-CN'];
    var name = EXT_DISPLAY[ext] || ext.toUpperCase();
    return name + ' ' + (W[kind] || W.text);
  }
  function typeLabelOf(item)  {
    var L = typeLabels();
    var F = TYPE_LABELS['zh-CN'] || {};
    if (!item) return L.other || F.other || '文件';
    if (item.dir) return L.folder || F.folder || '文件夹';
    var k = typeKeyOf(item);
    if (k === 'archive' || k === 'image' || k === 'video' || k === 'audio') return L[k] || F[k] || k;
    var ext = String(item.ext || extOfName(item.name || '')).toLowerCase();
    var t = textTypeLabel(ext);
    if (t) return t;
    return L[k] || F[k] || L.other || k;
  }
  function typeTextOf(item)  {
    var L = typeLabels();
    if (item && item.dir) return L.folder || '文件夹';
    var ext = item && item.ext ? String(item.ext).toLowerCase() : '';
    if (!ext) {
      var nm = String(item && item.name || '').toLowerCase();
      var dot = nm.lastIndexOf('.');
      if (dot > 0 && dot < nm.length - 1) ext = nm.slice(dot + 1);
    }
    var latin = (S.lang === 'en' || S.lang === 'es' || S.lang === 'ko');
    var tail = ext ? (latin ? ' (.' + ext + ')' : '（.' + ext + '）') : '';
    return (L.file || '文件') + ' · ' + typeLabelOf(item) + tail;
  }
  function isArchive(name)  {
    return /\.(zip|tar\.gz|tgz)$/i.test(name);
  }
  function isEditable(ext)  {
    var list = BOOT.editExt || [];
    return list.indexOf(String(ext).toLowerCase()) !== -1;
  }
  function pathJoin(a,  b)  { return a ? a + '/' + b : b; }
  function parentOf(p)  { var i = p.lastIndexOf('/'); return i === -1 ? '' : p.slice(0, i); }
  function baseName(p)  { var i = p.lastIndexOf('/'); return i === -1 ? p : p.slice(i + 1); }

  /* ---------- i18n 应用 ---------- */
  function applyI18n()  {
    document.documentElement.lang = S.lang;
    all('[data-i18n]').forEach(function (node)  {
      var key = node.getAttribute('data-i18n');
      node.textContent = T(key);
    });
    all('[data-i18n-ph]').forEach(function (node)  {
      node.setAttribute('placeholder', T(node.getAttribute('data-i18n-ph')));
    });
    document.title = BOOT.title + ' · ' + T('all_files');
    $('sortLabel').textContent = T('sort_' + S.sort);
    if (S.dirStats) paintDirStats(S.dirStats);
  }

  /* ---------- 主题 ---------- */
  function applyTheme()  {
    var pref = (S.settings && S.settings.theme) || 'system';
    var dark = pref === 'dark' || (pref === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    var html = document.documentElement;
    html.setAttribute('data-theme', dark ? 'dark' : 'light');
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      var appBg = '';
      try { appBg = getComputedStyle(html).getPropertyValue('--app').trim(); } catch (e) {}
      meta.setAttribute('content', appBg || (dark ? '#0b1019' : '#ffffff'));
    }
  }
  if (window.matchMedia) {
    try {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function ()  {
        if ((S.settings.theme || 'system') === 'system') applyTheme();
      });
    } catch (e) {}
  }

  /* ---------- 提示 ---------- */
  var toastTimer = null;
  function toast(msg,  isErr)  {
    var box = $('toaster');
    var node = document.createElement('div');
    node.className = 'toast' + (isErr ? ' err' : '');
    node.textContent = msg;
    box.appendChild(node);
    requestAnimationFrame(function ()  { node.classList.add('on'); });
    setTimeout(function ()  {
      node.classList.remove('on');
      setTimeout(function ()  { if (node.parentNode) node.parentNode.removeChild(node); }, 260);
    }, isErr ? 3600 : 2200);
  }

  function showProgress(text,  pct)  {
    var box = $('progress');
    box.classList.add('on');
    $('progressText').textContent = text || '';
    $('progressPct').textContent = pct === null || pct === undefined ? '' : Math.round(pct) + '%';
    $('progressBar').style.width = (pct || 0) + '%';
  }
  function hideProgress()  {
    setTimeout(function ()  {
      $('progress').classList.remove('on');
      $('progressBar').style.width = '0%';
    }, 320);
  }

  /* ---------- 网络 ---------- */
  function api(name,  body,  method)  {
    var opts = {
      method: method || 'POST',
      headers: { 'X-CSRF-Token': BOOT.csrf || '', 'X-Lang': S.lang, 'Content-Type': 'application/json' },
      credentials: 'same-origin'
    };
    var url = '?api=' + encodeURIComponent(name);
    if (opts.method === 'GET') {
      if (body) {
        var qs = [];
        Object.keys(body).forEach(function (k)  {
          if (body[k] !== undefined && body[k] !== null) qs.push(encodeURIComponent(k) + '=' + encodeURIComponent(body[k]));
        });
        if (qs.length) url += '&' + qs.join('&');
      }
      opts.headers = { 'X-Lang': S.lang };
    } else {
      opts.body = JSON.stringify(body || {});
    }
    return fetch(url, opts).then(function (r)  {
      if (r.status === 401) {
        location.reload();
        throw new Error('unauthorized');
      }
      return r.json().catch(function ()  {
        throw new Error('服务器返回异常');
      });
    }).then(function (res)  {
      if (!res || !res.ok) throw new Error((res && res.error) || '操作失败');
      return res;
    });
  }

  /* ---------- 弹层 ---------- */
  var backdrop = $('backdrop');
  function openBackdrop()  { backdrop.classList.add('on'); }
  function closeBackdrop()  {
    backdrop.classList.remove('on');
    if (!el('.sheet.on') && !el('.dialog.on')) {
      // 保持
    }
  }
  function openSheet(title,  hint)  {
    $('sheetTitle').textContent = title || '';
    $('sheetHint').textContent = hint || '';
    $('sheetBody').innerHTML = '';
    $('sheet').classList.add('on');
    document.body.classList.add('sheet-open');
    openBackdrop();
    return $('sheetBody');
  }
  function closeSheet()  {
    $('sheet').classList.remove('on');
    $('sheetBody').innerHTML = '';
    if (!$('settingsSheet').classList.contains('on') && !$('dialog').classList.contains('on')) {
      closeBackdrop();
      document.body.classList.remove('sheet-open');
    }
  }

  /* ---------- 磁贴菜单：更多 / 已选 / 打开方式 通用渲染 ---------- */
  function tileMenu(items)  {
    var html = '<div class="creategrid tilegrid">';
    items.forEach(function (it)  {
      if (!it) return;
      html += '<button type="button" class="createitem' + (it.danger ? ' is-danger' : '') + '" data-act="' + it.act + '">'
        + '<span class="cico cico-' + (it.color || 'blue') + '">' + icon(it.icon, 'ic') + '</span>'
        + '<span class="cname">' + esc(it.label) + '</span></button>';
    });
    html += '</div><div class="sheet-foot"><button type="button" class="btn btn-ghost" data-sheetclose="1">'
      + esc(T('close')) + '</button></div>';
    return html;
  }
  function bindSheetActions(body,  handler)  {
    body.onclick = function (e)  {
      var t = e.target;
      if (!t || !t.closest) return;
      if (t.closest('[data-sheetclose]')) { closeSheet(); return; }
      var b = t.closest('[data-act]');
      if (!b) return;
      handler(b.getAttribute('data-act'), b);
    };
  }

  /* ---------- 新建面板 ---------- */
  var CREATE_ITEMS = [
    { act: 'upload', icon: 'upload', cls: 'blue', key: 'upload' },
    { act: 'mkdir', icon: 'folderplus', cls: 'orange', key: 'new_folder' },
    { act: 'newfile', icon: 'fileplus', cls: 'green', key: 'new_text' },
    { act: 'github', icon: 'github', cls: 'dark', key: 'github_dl' },
    { act: 'uploadFolder', icon: 'cloud', cls: 'teal', key: 'upload_folder' },
    { act: 'url', icon: 'link', cls: 'violet', key: 'url_dl' },
    { act: 'refresh', icon: 'refresh', cls: 'gray', key: 'refresh' }
  ];
  function openCreateSheet()  {
    var body = openSheet(T('create'), '');
    var html = '<div class="creategrid">';
    CREATE_ITEMS.forEach(function (it)  {
      html += '<button type="button" class="createitem" data-cact="' + it.act + '">'
        + '<span class="cico cico-' + it.cls + '">' + icon(it.icon, 'ic') + '</span>'
        + '<span class="cname">' + esc(T(it.key)) + '</span></button>';
    });
    html += '</div><div class="sheet-foot"><button type="button" class="btn btn-ghost" id="createClose">'
      + esc(T('close')) + '</button></div>';
    body.innerHTML = html;
    on(body.querySelector('#createClose'), 'click', closeSheet);
    on(body.querySelector('.creategrid'), 'click', function (e)  {
      var b = e.target.closest('[data-cact]');
      if (!b) return;
      var act = b.getAttribute('data-cact');
      closeSheet();
      if (act === 'upload') $('fileInput').click();
      else if (act === 'uploadFolder') $('folderInput').click();
      else if (act === 'mkdir') newFolder();
      else if (act === 'newfile') newFile();
      else if (act === 'url') openUrlSheet();
      else if (act === 'github') openGithubSheet();
      else if (act === 'refresh') refresh();
    });
  }

  function menuItem(act,  iconName,  label,  hint,  cls)  {
    return '<button class="menu-item ' + (cls || '') + '" data-act="' + act + '">'
      + '<span class="mi">' + icon(iconName, 'ic-sm') + '</span>'
      + '<span class="mt">' + esc(label) + (hint ? '<small>' + esc(hint) + '</small>' : '') + '</span>'
      + '</button>';
  }

  /* ---------- 对话框 ---------- */
  var dlgResolve = null;
  function dialog(opts)  {
    return new Promise(function (resolve)  {
      dlgResolve = resolve;
      $('dlgTitle').textContent = opts.title || '';
      $('dlgText').innerHTML = opts.text || '';
      $('dlgText').style.display = opts.text ? '' : 'none';
      var input = $('dlgInput');
      if (opts.input === false) {
        input.hidden = true;
      } else {
        input.hidden = false;
        input.value = opts.value || '';
        input.placeholder = opts.placeholder || '';
        input.type = opts.type || 'text';
      }
      $('dlgExtra').innerHTML = opts.extra || '';
      $('dlgHint').textContent = '';
      $('dlgOk').textContent = opts.okText || T('ok');
      $('dlgOk').className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');
      $('dlgCancel').textContent = opts.cancelText || T('cancel');
      $('dlgCancel').hidden = !!opts.single;
      $('dialog').classList.add('on');
      openBackdrop();
      if (opts.input !== false) {
        setTimeout(function ()  { input.focus(); if (opts.select !== false) input.select(); }, 120);
      }
    });
  }
  function closeDialog()  {
    $('dialog').classList.remove('on');
    if (!$('sheet').classList.contains('on') && !$('settingsSheet').classList.contains('on')) closeBackdrop();
  }
  function dlgDone(value)  {
    var fn = dlgResolve;
    dlgResolve = null;
    closeDialog();
    if (fn) fn(value);
  }
  on($('dlgOk'), 'click', function ()  {
    var input = $('dlgInput');
    dlgDone(input.hidden ? true : input.value);
  });
  on($('dlgCancel'), 'click', function ()  { dlgDone(null); });
  on($('dialog'), 'keydown', function (e)  {
    if (e.key === 'Enter') {
      e.preventDefault();
      var input = $('dlgInput');
      dlgDone(input.hidden ? true : input.value);
    }
  });

  /* ============================================================
     1. 文件列表
     ============================================================ */
  function chipList()  {
    return [
      { key: 'all', label: T('all_files'), icon: 'folder' },
      { key: 'folder', label: T('folders') || '文件夹', icon: 'folder' },
      { key: 'image', label: T('images') || '图片', icon: 'image' },
      { key: 'video', label: T('videos') || '视频', icon: 'video' },
      { key: 'audio', label: T('audios') || '音频', icon: 'audio' },
      { key: 'doc', label: T('docs') || '文档', icon: 'doc' },
      { key: 'text', label: T('texts') || '文本', icon: 'text' },
      { key: 'archive', label: T('archives') || '压缩包', icon: 'archive' }
    ];
  }
  function renderChips()  {
    $('chips').innerHTML = chipList().map(function (c)  {
      return '<button class="chip' + (S.kind === c.key ? ' on' : '') + '" data-kind="' + c.key + '">'
        + icon(c.icon, 'ic-sm') + '<span>' + esc(c.label) + '</span></button>';
    }).join('');
  }

  function sortItems(items)  {
    var dir = S.dir;
    var sorted = items.slice();
    sorted.sort(function (a,  b)  {
      if (a.dir !== b.dir) return a.dir ? -1 : 1;
      var r = 0;
      if (S.sort === 'size') r = (a.size || 0) - (b.size || 0);
      else if (S.sort === 'time') r = (a.mtime || 0) - (b.mtime || 0);
      else if (S.sort === 'type') r = String(a.ext || '').localeCompare(String(b.ext || ''));
      else r = String(a.name).localeCompare(String(b.name), 'zh-Hans-CN', { numeric: true });
      if (!r && S.sort !== 'name') r = String(a.name).localeCompare(String(b.name), 'zh-Hans-CN', { numeric: true });
      return r * dir;
    });
    return sorted;
  }

  function visibleItems()  {
    var items = S.items.slice();
    if (S.kind !== 'all') {
      items = items.filter(function (it)  { return it.kind === S.kind; });
    }
    return sortItems(items);
  }

  function rowHTML(it,  idx)  {
    var kind = kindClass(it.kind);
    var selected = !!S.sel[it.path || it.name];
    var meta = it.dir ? T('folders') || '文件夹' : (it.sizeText || fmtSize(it.size));
    var time = fmtDate(it.mtime);
    var nameHtml = esc(it.name);
    if (S.searchQ) {
      var q = S.searchQ.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      nameHtml = nameHtml.replace(new RegExp('(' + q + ')', 'ig'), '<mark>$1</mark>');
    }
    var sub = it.dir ? T('folders') || '文件夹' : meta;
    if (S.searchMode && it.path) sub = it.path;
    return '<div class="row' + (selected ? ' selected' : '') + '" data-i="' + idx + '" data-path="' + esc(it.path) + '">'
      + '<div class="r-lead"><span class="r-ico k-' + kind + '">' + icon(kindIcon(it.kind)) + '</span>'
      + '<span class="r-check"><i></i></span></div>'
      + '<div class="r-main"><div class="r-name">' + nameHtml + '</div>'
      + '<div class="r-meta">' + esc(sub) + (it.dir ? '' : '<span class="dot"></span>' + esc(time)) + '</div></div>'
      + '<div class="r-col r-size">' + (it.dir ? '—' : esc(meta)) + '</div>'
      + '<div class="r-col r-time">' + esc(time) + '</div>'
      + '<div class="r-col r-perm">' + (it.perm ? '<code>' + esc(it.perm) + '</code>' : '') + '</div>'
      + '<button class="r-act" data-act="rowmore" aria-label="more">' + icon('more', 'ic-sm') + '</button>'
      + '</div>';
  }

  function render()  {
    var list = $('list');
    var items = visibleItems();
    var showPerm = !!S.settings.show_perms;
    list.className = 'list' + (S.selecting ? ' selecting' : '') + (showPerm ? '' : ' hide-perm') + (S.viewMode === 'grid' ? ' grid' : '');
    $('thead').classList.toggle('hide-perm', !showPerm);
    if (S.loading) {
      list.innerHTML = '<div class="skel"><i style="width:34px;height:34px"></i><i style="flex:1;height:12px;max-width:180px"></i></div>'
        + '<div class="skel"><i style="width:34px;height:34px"></i><i style="flex:1;height:12px;max-width:140px"></i></div>'
        + '<div class="skel"><i style="width:34px;height:34px"></i><i style="flex:1;height:12px;max-width:220px"></i></div>';
      $('empty').classList.remove('on');
      return;
    }
    list.innerHTML = items.map(rowHTML).join('');
    var empty = items.length === 0;
    $('empty').classList.toggle('on', empty);
    if (empty) {
      var isSearch = S.searchMode && S.searchQ;
      $('emptyTitle').textContent = isSearch ? (T('no_result') || '没有找到匹配的文件') : (S.view === 'recent' ? T('recent_empty') : T('empty'));
      $('emptySub').textContent = isSearch ? (T('try_other') || '换个关键词试试') : T('empty_sub');
      $('emptyBtn').style.display = (isSearch || S.view !== 'files') ? 'none' : 'flex';
    }
    updateTitle();
    updateSelUI();
  }

  function updateTitle()  {
    var title = $('tbTitle');
    var sub = $('tbSub');
    var back = $('btnBack');
    var showBack = (S.view === 'files' && !!S.path) || S.view !== 'files' || S.searchMode;
    back.hidden = !showBack;
    if (S.searchMode && S.searchQ) {
      title.textContent = T('search');
      sub.textContent = S.searchQ + ' · ' + (S.items.length || 0) + ' ' + T('items');
    } else if (S.view === 'recent') {
      title.textContent = T('recent');
      sub.textContent = T('recent_sub') || '按修改时间排序';
    } else {
      title.textContent = S.path ? baseName(S.path) : (BOOT.title || T('all_files'));
      sub.textContent = S.path ? '/' + S.path : (BOOT.rootName || '/') + ' · ' + (BOOT.server || '');
    }
    document.title = (S.path ? baseName(S.path) : (BOOT.title || '易优PHP文件管理器')) + ' · ' + T('files');
  }

  function updateStorage(st)  {
    if (!st) return;
    S.storage = st;
    paintStorage();
  }

  /* 存储空间卡（设置 · 通用）：可用 / 已用 / 总量 / 进度条 / 上传 */
  function paintStorage()  {
    var st = S.storage;
    var card = $('setStoreCard');
    /* 读不到容量（known = 0）时整块隐藏，不在界面上留空壳或破折号 */
    if (!st || !Number(st.known)) {
      if (card) card.hidden = true;
      return;
    }
    if (card) card.hidden = false;
    var pct = Math.max(0, Math.min(100, st.percent || 0));
    var free = $('setStoreFree');
    if (free) free.innerHTML = esc(st.freeText) + '<small>' + esc(T('free')) + '</small>';
    var bar = $('setStoreBar');
    if (bar) bar.style.width = pct + '%';
    var used = $('setStoreUsed');
    if (used) used.textContent = T('used') + ' ' + st.usedText;
    var total = $('setStoreTotal');
    if (total) total.textContent = T('total') + ' ' + st.totalText;
    var loc = $('setStorePath');
    if (loc) loc.textContent = (S.path ? '/' + S.path : (BOOT.rootName || '/'));
  }

  /* ---------- 加载 ---------- */
  function load(path,  opts)  {
    opts = opts || {};
    S.searchMode = false;
    S.searchQ = '';
    S.view = opts.view || 'files';
    if (S.view === 'files') S.path = path || '';
    S.loading = true;
    S.items = [];
    exitSelect();
    render();
    syncNav();
    var req;
    if (S.view === 'recent') req = api('recent', { path: '' }, 'GET');
    else req = api('list', { path: S.path }, 'GET');
    return req.then(function (res)  {
      S.items = (res.items || res.data || []).map(normalizeItem);
      if (res.storage) updateStorage(res.storage);
      S.loading = false;
      render();
      if (S.view === 'files' && !S.path && !S.searchMode) loadStorage();
      loadDirStats();
    }).catch(function (e)  {
      S.loading = false;
      S.items = [];
      render();
      hideDirStats();
      toast(e.message || '加载失败', true);
    });
  }

  function normalizeItem(it)  {
    return {
      name: it.name,
      path: it.path,
      dir: !!it.dir,
      size: Number(it.size) || 0,
      sizeText: it.sizeText || fmtSize(it.size),
      mtime: Number(it.mtime) || 0,
      ext: it.ext || '',
      kind: it.kind || (it.dir ? 'folder' : 'file'),
      perm: it.perm || '',
      permText: it.permText || '',
      owner: it.owner || '',
      group: it.group || '',
      /* 仅文件夹详情会带：子文件数 / 子文件夹数 / 是否因目录过大被截断统计 */
      subFiles: (it.subFiles == null) ? -1 : Number(it.subFiles),
      subDirs: (it.subDirs == null) ? -1 : Number(it.subDirs),
      sizePartial: !!it.sizePartial
    };
  }

  function loadStorage()  {
    api('storage', {}, 'GET').then(function (res)  { updateStorage(res.data); }).catch(function ()  {});
  }

  /* ---------- 当前文件夹统计：文件数 / 文件夹数 / 总大小 ---------- */
  var statsSeq = 0;
  var statsTimer = null;
  function fmtCount(n)  {
    n = Math.max(0, Number(n) || 0);
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }
  function hideDirStats()  {
    var box = $('listStats');
    if (!box) return;
    box.hidden = true;
    box.innerHTML = '';
    box.removeAttribute('title');
    S.dirStats = null;
  }
  function paintDirStats(st)  {
    var box = $('listStats');
    if (!box) return;
    if (!st || S.view !== 'files' || S.searchMode) { hideDirStats(); return; }
    S.dirStats = st;
    var approx = Number(st.partial) ? '≥ ' : '';
    var size = st.sizeText || fmtSize(st.size);
    box.innerHTML = '<span class="st">' + icon('file', 'ic') + '<b>' + approx + fmtCount(st.files) + '</b>' + esc(T('zip_files')) + '</span>'
      + '<span class="st">' + icon('folder', 'ic') + '<b>' + approx + fmtCount(st.dirs) + '</b>' + esc(T('zip_folders')) + '</span>'
      + '<span class="st">' + icon('drive', 'ic') + '<b>' + approx + esc(size) + '</b></span>';
    box.title = T('stat_hint') + (Number(st.partial) ? ' · ' + T('stat_partial') : '');
    box.hidden = false;
  }
  function loadDirStats()  {
    var box = $('listStats');
    if (!box) return;
    var seq = ++statsSeq;
    if (statsTimer) { clearTimeout(statsTimer); statsTimer = null; }
    hideDirStats();
    if (S.view !== 'files' || S.searchMode) return;
    /* 目录较大时统计稍慢，超过 160ms 才显示“统计中”，避免闪烁 */
    statsTimer = setTimeout(function ()  {
      if (seq !== statsSeq) return;
      box.innerHTML = '<span class="st st-load">' + esc(T('stat_loading')) + '</span>';
      box.hidden = false;
    }, 160);
    api('dirstat', { path: S.path }, 'GET').then(function (res)  {
      if (seq !== statsSeq) return;
      if (statsTimer) { clearTimeout(statsTimer); statsTimer = null; }
      paintDirStats(res.data || null);
    }).catch(function ()  {
      if (seq !== statsSeq) return;
      if (statsTimer) { clearTimeout(statsTimer); statsTimer = null; }
      hideDirStats();
    });
  }

  function refresh()  {
    return load(S.path, { view: S.view });
  }

  function syncNav()  {
    all('.nav-item').forEach(function (b)  { b.classList.toggle('active', b.getAttribute('data-view') === S.view); });
    all('.tab').forEach(function (b)  {
      var v = b.getAttribute('data-view');
      b.classList.toggle('on', v === S.view || (v === 'settings' && $('settingsSheet').classList.contains('on')));
    });
  }

  /* ---------- 搜索 ---------- */
  function openSearch()  {
    S.searchMode = true;
    $('searchBar').classList.add('on');
    $('btnSearch').classList.add('on');
    setTimeout(function ()  { $('searchInput').focus(); }, 60);
  }
  function closeSearch()  {
    S.searchMode = false;
    $('searchBar').classList.remove('on');
    $('btnSearch').classList.remove('on');
    $('searchInput').value = '';
    $('searchInput').blur();
    refresh();
  }
  var searchTimer = null;
  function doSearch(q)  {
    q = q.trim();
    if (!q) { refresh(); return; }
    S.searchQ = q;
    S.searchMode = true;
    S.loading = true;
    hideDirStats();
    render();
    api('search', { q: q, path: S.view === 'files' ? S.path : '' }, 'GET').then(function (res)  {
      S.items = (res.items || []).map(normalizeItem);
      S.loading = false;
      render();
    }).catch(function (e)  {
      S.loading = false;
      render();
      toast(e.message, true);
    });
  }

  /* ============================================================
     2. 选择模式
     ============================================================ */
  function enterSelect(path)  {
    S.selecting = true;
    if (path) S.sel[path] = true;
    S.selCount = Object.keys(S.sel).length;
    $('selBar').classList.add('on');
    $('selActions').classList.add('on');
    $('fab').style.display = 'none';
    $('tabbar').style.display = 'none';
    render();
  }
  function exitSelect()  {
    S.selecting = false;
    S.sel = {};
    S.selCount = 0;
    $('selBar').classList.remove('on');
    $('selActions').classList.remove('on');
    $('fab').style.display = '';
    $('tabbar').style.display = '';
    if (!S.loading) render();
  }
  function updateSelUI()  {
    S.selCount = Object.keys(S.sel).length;
    $('selCount').textContent = S.selCount;
    all('[data-sel]').forEach(function (b)  {
      var act = b.getAttribute('data-sel');
      if (act === 'link') b.disabled = S.selCount !== 1;
      if (act === 'compress') b.disabled = S.selCount === 0;
    });
    if (S.selecting) {
      var items = visibleItems();
      var allSel = items.length > 0 && items.every(function (it)  { return S.sel[it.path]; });
      $('btnSelAll').textContent = allSel ? T('none') : T('select_all');
    }
  }
  function toggleSelect(path)  {
    if (S.sel[path]) delete S.sel[path];
    else S.sel[path] = true;
    S.selCount = Object.keys(S.sel).length;
    if (S.selCount === 0) { exitSelect(); return; }
    var row = el('.row[data-path="' + cssEsc(path) + '"]');
    if (row) row.classList.toggle('selected', !!S.sel[path]);
    updateSelUI();
  }
  function selectAll()  {
    var items = visibleItems();
    var allSel = items.length > 0 && items.every(function (it)  { return S.sel[it.path]; });
    if (allSel) { S.sel = {}; }
    else { items.forEach(function (it)  { S.sel[it.path] = true; }); }
    S.selCount = Object.keys(S.sel).length;
    if (!S.selCount) { exitSelect(); return; }
    render();
  }
  function invertSelect()  {
    var items = visibleItems();
    var next = {};
    items.forEach(function (it)  { if (!S.sel[it.path]) next[it.path] = true; });
    S.sel = next;
    S.selCount = Object.keys(S.sel).length;
    if (!S.selCount) { exitSelect(); return; }
    render();
  }
  function cssEsc(s)  { return String(s).replace(/["\\]/g, '\\$&'); }
  function selectedPaths()  { return Object.keys(S.sel); }
  function selectedItems()  {
    var map = {};
    S.items.forEach(function (it)  { map[it.path] = it; });
    return selectedPaths().map(function (p)  { return map[p]; }).filter(Boolean);
  }

  /* ============================================================
     3. 行交互
     ============================================================ */
  var pressTimer = null;
  var pressMoved = false;
  var pressTarget = null;

  function bindList()  {
    on($('list'), 'click', function (e)  {
      var more = e.target.closest('[data-act="rowmore"]');
      var row = e.target.closest('.row');
      if (!row) return;
      var idx = Number(row.getAttribute('data-i'));
      var item = visibleItems()[idx];
      if (!item) return;
      if (more) { e.stopPropagation(); openItemSheet(item); return; }
      if (S.selecting) { toggleSelect(item.path); return; }
      if (item.dir) {
        if (S.view === 'files') load(item.path);
        else load(item.path);
      } else {
        openItem(item);
      }
    });

    on($('list'), 'pointerdown', function (e)  {
      var row = e.target.closest('.row');
      if (!row || e.button === 2) return;
      pressMoved = false;
      pressTarget = row;
      clearTimeout(pressTimer);
      pressTimer = setTimeout(function ()  {
        if (pressMoved || !pressTarget) return;
        var idx = Number(pressTarget.getAttribute('data-i'));
        var item = visibleItems()[idx];
        if (!item) return;
        if (navigator.vibrate) { try { navigator.vibrate(12); } catch (err) {} }
        if (!S.selecting) enterSelect(item.path);
        else toggleSelect(item.path);
        pressTarget = null;
      }, 460);
    });
    on($('list'), 'pointermove', function (e)  {
      if (!pressTarget) return;
      var dx = Math.abs(e.movementX || 0), dy = Math.abs(e.movementY || 0);
      if (dx > 2 || dy > 2) { pressMoved = true; clearTimeout(pressTimer); }
    });
    on($('list'), 'pointerup', function ()  { clearTimeout(pressTimer); pressTarget = null; });
    on($('list'), 'pointercancel', function ()  { clearTimeout(pressTimer); pressTarget = null; });
    on($('list'), 'contextmenu', function (e)  {
      var row = e.target.closest('.row');
      if (!row) return;
      e.preventDefault();
      var idx = Number(row.getAttribute('data-i'));
      var item = visibleItems()[idx];
      if (item) openItemSheet(item);
    });
  }

  function openItem(item)  {
    if (item.dir) {
      if (S.view === 'files') load(item.path);
      else load(item.path);
      return;
    }
    var kind = item.kind;
    if (kind === 'text' || (isEditable(item.ext) && kind !== 'image')) {
      previewFile(item);
      return;
    }
    previewFile(item);
  }

  /* ---------- 单文件操作菜单（图标磁贴） ---------- */
  function openItemSheet(item)  {
    var body = openSheet(item.name, item.dir ? (typeLabelOf(item) + ' · /' + item.path) : (typeLabelOf(item) + ' · ' + item.sizeText + ' · ' + fmtDate(item.mtime)));
    var items = [];
    items.push({ act: 'open', icon: item.dir ? 'folder' : (item.kind === 'image' ? 'image' : 'eye'),
      label: item.dir ? T('open') : T('preview'), color: 'blue' });
    if (!item.dir && isZipItem(item)) items.push({ act: 'zipview', icon: 'archive', label: T('zip_preview'), color: 'blue' });
    if (!item.dir && isEditable(item.ext)) items.push({ act: 'edit', icon: 'edit', label: T('editor'), color: 'amber' });
    if (!item.dir) items.push({ act: 'download', icon: 'download', label: T('download'), color: 'indigo' });
    items.push({ act: 'link', icon: 'link', label: T('link'), color: 'teal' });
    items.push({ act: 'rename', icon: 'edit', label: T('rename'), color: 'orange' });
    items.push({ act: 'move', icon: 'folder', label: T('move'), color: 'violet' });
    items.push({ act: 'chmod', icon: 'lock', label: T('chmod'), color: 'slate' });
    items.push({ act: 'copy', icon: 'copy', label: T('copy'), color: 'gray' });
    items.push({ act: 'cut', icon: 'cut', label: T('cut'), color: 'gray' });
    if (isArchive(item.name)) items.push({ act: 'extract', icon: 'unzip', label: T('extract'), color: 'green' });
    items.push({ act: 'compress', icon: 'zip', label: T('compress'), color: 'green' });
    items.push({ act: 'info', icon: 'info', label: T('info'), color: 'slate' });
    items.push({ act: 'delete', icon: 'trash', label: T('delete'), danger: true });
    body.innerHTML = tileMenu(items);
    bindSheetActions(body, function (act)  {
      closeSheet();
      setTimeout(function ()  { handleItemAction(act, item); }, 60);
    });
  }

  function handleItemAction(act,  item)  {
    switch (act) {
      case 'open':
        if (item.dir) load(item.path); else previewFile(item);
        break;
      case 'zipview':
        previewFile(item);
        break;
      case 'edit':
        openEditor(item);
        break;
      case 'download':
        downloadItem(item);
        break;
      case 'link':
        copyLink(item);
        break;
      case 'rename':
        doRename(item);
        break;
      case 'move':
        openMove([item.path], [item]);
        break;
      case 'chmod':
        openChmod([item.path], [item]);
        break;
      case 'copy':
        setClipboard('copy', [item.path]);
        break;
      case 'cut':
        setClipboard('cut', [item.path]);
        break;
      case 'extract':
        doExtract(item);
        break;
      case 'compress':
        openCompressSheet([item.path], item.dir ? item.name : item.name.replace(/\.[^.]+$/, ''));
        break;
      case 'info':
        showInfo(item);
        break;
      case 'delete':
        doDelete([item.path], [item.name]);
        break;
    }
  }

  /* ============================================================
     4. 操作实现
     ============================================================ */
  function setClipboard(mode,  paths)  {
    S.clip = { mode: mode, paths: paths.slice() };
    updateClipBar();
    exitSelect();
    toast((mode === 'cut' ? T('cut_tip') : T('copied_tip')));
  }
  function updateClipBar()  {
    var bar = $('clipBar');
    var sc = $('scroll');
    if (!S.clip || !S.clip.paths.length) {
      bar.classList.remove('on');
      if (sc) sc.classList.remove('clip-on');
      return;
    }
    bar.classList.add('on');
    if (sc) sc.classList.add('clip-on');
    var label = S.clip.mode === 'cut' ? T('clip_cut') : T('clip_copy');
    $('clipText').innerHTML = '<b>' + esc(label) + '</b> · ' + S.clip.paths.length + ' ' + T('items');
    $('btnPaste').textContent = T('paste');
  }
  function clearClipboard()  {
    S.clip = null;
    updateClipBar();
  }
  function pasteInto(dest)  {
    if (!S.clip) return;
    var clip = S.clip;
    var act = clip.mode === 'cut' ? 'move' : 'copy';
    showProgress(act === 'move' ? (T('moved_tip') || '移动中') : (T('copying') || '复制中'), null);
    api(act, { paths: clip.paths, dest: dest }).then(function (res)  {
      hideProgress();
      toast((act === 'move' ? T('moved_tip') : T('copy_ok')) + (res.done && res.done.length ? ' · ' + res.done.length + ' ' + T('items') : ''));
      var failed = (res && res.failed) ? res.failed : [];
      if (failed.length) toast(failed.join('、'), true);
      /* 粘贴请求结束后统一的收起入口：复制与剪切都在这里清空剪贴板，
         这样底部「待复制 / 粘贴」提示条不会在粘贴完成后继续挂着。
         失败项已通过 toast 提示，不保留剪贴板，避免提示条与内容长期不一致。 */
      clearClipboard();
      refresh();
    }).catch(function (e)  {
      hideProgress();
      toast(e.message, true);
    });
  }

  function doDelete(paths,  names)  {
    dialog({
      title: T('delete'),
      text: (names.length === 1 ? esc(names[0]) : names.length + ' ' + T('items')) + ' — ' + (T('delete_confirm') || '删除后不可恢复，确定继续吗？'),
      input: false,
      danger: true,
      okText: T('delete')
    }).then(function (ok)  {
      if (!ok) return;
      api('delete', { paths: paths }).then(function (res)  {
        toast(T('deleted_tip') + (res.deleted ? ' · ' + res.deleted : ''));
        exitSelect();
        refresh();
      }).catch(function (e)  { toast(e.message, true); });
    });
  }

  function doRename(item)  {
    var initial = item.name;
    var dot = !item.dir && initial.lastIndexOf('.') > 0 ? initial.lastIndexOf('.') : initial.length;
    dialog({ title: T('rename'), text: T('rename_to'), value: initial, placeholder: initial }).then(function (val)  {
      if (val === null) return;
      val = String(val).trim();
      if (!val || val === item.name) return;
      api('rename', { path: item.path, name: val }).then(function ()  {
        toast(T('saved_tip'));
        refresh();
      }).catch(function (e)  { toast(e.message, true); });
    });
    setTimeout(function ()  {
      var input = $('dlgInput');
      try { input.setSelectionRange(0, dot); } catch (e) {}
    }, 140);
  }

  function parentPath(p)  {
    var i = String(p).lastIndexOf('/');
    return i <= 0 ? '' : String(p).slice(0, i);
  }

  /* 修改权限：三位八进制，支持递归 */
  function openChmod(paths,  items,  probed)  {
    if (!paths.length) return;
    var single = paths.length === 1 && items && items[0];
    /* 「显示权限与拥有者」关着时，列表数据里没有权限列，弹窗标题上也就看不到
       当前权限。这里单独取一次详情再打开；probed 保证只补取一次，不会来回打转。 */
    if (!probed && single && !single.perm && single.path) {
      api('info', { path: single.path }, 'GET').then(function (res) {
        openChmod(paths, [(res && res.item) ? normalizeItem(res.item) : items], true);
      }).catch(function ()  {
        openChmod(paths, items, true);
      });
      return;
    }
    var isDir = !!(single && items[0].dir);
    var presets = ['644', '755', '600', '775', '777'];
    var extra = '<div style="display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 10px">'
      + presets.map(function (m)  {
        return '<button type="button" data-preset="' + m + '" style="height:30px;padding:0 12px;border-radius:8px;border:1px solid var(--line);background:var(--surface-2);color:var(--text-2);font-size:12px">' + m + '</button>';
      }).join('')
      + '</div>'
      + '<input class="field" id="chmodMode" inputmode="numeric" maxlength="3" value="' + (isDir ? '755' : '644') + '" style="height:42px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface-2);padding:0 13px;width:100%;margin-bottom:8px">'
      + '<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--text-2)">'
      + '<input type="checkbox" id="chmodRec"' + (paths.length > 1 || isDir ? '' : ' disabled') + '>' + esc(T('chmod_recursive')) + '</label>';
    var label = single ? items[0].name : paths.length + ' ' + T('items');
    dialog({
      title: T('chmod'),
      text: esc(label) + (single && items[0].perm ? ' · ' + esc(items[0].perm) : ''),
      input: false,
      extra: extra,
      okText: T('ok')
    }).then(function (ok)  {
      if (!ok) return;
      var inp = document.getElementById('chmodMode');
      var mode = (inp ? inp.value : '').replace(/[^0-7]/g, '');
      if (!/^[0-7]{3}$/.test(mode)) { toast('644 / 755', true); return; }
      var rec = document.getElementById('chmodRec');
      api('chmod', { paths: paths, mode: mode, recursive: rec ? !!rec.checked : false }).then(function (res)  {
        toast(T('chmod_done') + ' · ' + (res.mode || mode));
        if (res.failed && res.failed.length) toast(res.failed.join('、'), true);
        refresh();
      }).catch(function (e)  { toast(e.message, true); });
    });
    setTimeout(function ()  {
      var box = document.getElementById('dlgExtra');
      if (!box) return;
      Array.prototype.forEach.call(box.querySelectorAll('[data-preset]'), function (b)  {
        b.addEventListener('click', function ()  {
          var inp = document.getElementById('chmodMode');
          if (inp) inp.value = b.getAttribute('data-preset');
          Array.prototype.forEach.call(box.querySelectorAll('[data-preset]'), function (x)  { x.style.borderColor = 'var(--line)'; x.style.color = 'var(--text-2)'; });
          b.style.borderColor = 'var(--accent)';
          b.style.color = 'var(--accent)';
        });
      });
    }, 80);
  }

  /* 移动文件 / 文件夹：目录浏览 + 移动到此 */
  function openMove(paths,  items)  {
    if (!paths.length) return;
    var cur = paths.length === 1 ? parentPath(paths[0]) : S.path;
    if (cur === null || cur === undefined) cur = S.path;
    var body = openSheet(T('move_to'), paths.length === 1 && items[0] ? items[0].name : paths.length + ' ' + T('items'));
    body.innerHTML = '<div class="mvpath" id="mvPath">/</div>'
      + '<div class="mvlist" id="mvList"></div>'
      + '<button class="btn btn-primary dlbtn" id="mvGo" style="margin-top:12px">' + icon('check', 'ic-sm') + esc(T('move_to')) + '</button>';
    function isBlocked(p)  {
      return paths.some(function (x)  { return p === x || p.indexOf(x + '/') === 0; });
    }
    function renderList()  {
      var box = body.querySelector('#mvList');
      body.querySelector('#mvPath').textContent = '/' + cur;
      box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--text-3);font-size:12px">' + esc(T('loading')) + '</div>';
      api('list', { path: cur }, 'GET').then(function (res)  {
        var dirs = (res.items || res.data || []).filter(function (it)  { return it.dir; });
        var html = cur !== '' ? menuItem('up', 'back', '..') : '';
        html += dirs.map(function (d)  {
          return menuItem('dir:' + d.path, 'folder', d.name, isBlocked(d.path) ? T('perm_denied') : '');
        }).join('');
        if (!html) html = '<div style="padding:18px;text-align:center;color:var(--text-3);font-size:12px">' + esc(T('empty')) + '</div>';
        box.innerHTML = html;
      }).catch(function (e)  {
        box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--text-3);font-size:12px">' + esc(e.message) + '</div>';
      });
    }
    body.onclick = function (e)  {
      var b = e.target.closest('[data-act]');
      if (!b) return;
      var act = b.getAttribute('data-act');
      if (act === 'up') { cur = parentPath(cur); renderList(); return; }
      if (act.indexOf('dir:') === 0) {
        var np = act.slice(4);
        if (isBlocked(np)) { toast(T('perm_denied'), true); return; }
        cur = np; renderList();
      }
    };
    on(body.querySelector('#mvGo'), 'click', function ()  {
      if (isBlocked(cur)) { toast(T('perm_denied'), true); return; }
      api('move', { paths: paths, dest: cur }).then(function (res)  {
        closeSheet();
        toast(T('move_done') + (res.done && res.done.length ? ' · ' + res.done.length + ' ' + T('items') : ''));
        if (res.failed && res.failed.length) toast(res.failed.join('、'), true);
        exitSelect();
        refresh();
      }).catch(function (err)  { toast(err.message, true); });
    });
    renderList();
  }

  function isImageName(name)  { return /\.(png|jpe?g|gif|webp|bmp|svg|ico|avif)$/i.test(name); }

  function downloadItem(item)  {
    window.location.href = '?api=download&path=' + encodeURIComponent(item.path);
  }

  function copyLink(item)  {
    api('link', { path: item.path }).then(function (res)  {
      copyText(res.url).then(function (ok)  {
        if (ok) toast(T('copied_tip'));
        else showLinkDialog(res.url);
      });
    }).catch(function (e)  { toast(e.message, true); });
  }
  function copyText(text)  {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function ()  { return true; }).catch(function ()  { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text)  {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) { return false; }
  }
  function showLinkDialog(url)  {
    dialog({ title: T('link'), text: esc(url), input: false }).then(function ()  {});
    setTimeout(function ()  {
      var p = $('dlgText');
      p.innerHTML = '<input class="field" readonly value="' + esc(url) + '" style="height:42px">';
      var inp = p.querySelector('input');
      if (inp) { inp.focus(); inp.select(); }
    }, 60);
  }

  function doExtract(item)  {
    var baseName = item.name.replace(/\.(tar\.gz|tgz|gz|zip)$/i, '');
    if (!baseName) baseName = 'extracted';
    var body = openSheet(T('extract_title') || T('extract'), item.name);
    body.innerHTML =
      '<div class="xmode" id="extMode">'
      + '<button type="button" class="xmode-item" data-m="folder">'
      + '<span class="xmi">' + icon('folder', 'ic') + '</span>'
      + '<span class="xmt"><b>' + esc(T('extract_folder')) + '</b><small>' + esc(T('extract_folder_hint')) + '</small></span>'
      + '<span class="xmk">' + icon('check', 'ic-sm') + '</span></button>'
      + '<button type="button" class="xmode-item" data-m="here">'
      + '<span class="xmi">' + icon('unzip', 'ic') + '</span>'
      + '<span class="xmt"><b>' + esc(T('extract_here')) + '</b><small>' + esc(T('extract_here_hint')) + '</small></span>'
      + '<span class="xmk">' + icon('check', 'ic-sm') + '</span></button>'
      + '</div>'
      + '<label class="cmpfield" id="extNameWrap" for="extName">'
      + '<span class="cmplabel">' + esc(T('extract_folder_name')) + '</span>'
      + '<input class="cmpinput" id="extName" value="' + esc(baseName) + '" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="120"></label>'
      + '<div class="sheet-foot">'
      + '<button type="button" class="btn btn-ghost" data-sheetclose="1">' + esc(T('cancel')) + '</button>'
      + '<button type="button" class="btn btn-primary" id="extGo">' + esc(T('extract_go')) + '</button></div>';

    var mode = 'folder';
    var modeBox = body.querySelector('#extMode');
    var nameWrap = body.querySelector('#extNameWrap');
    var nameInput = body.querySelector('#extName');
    function paint()  {
      Array.prototype.forEach.call(modeBox.querySelectorAll('[data-m]'), function (b)  {
        b.classList.toggle('on', b.getAttribute('data-m') === mode);
      });
      nameWrap.hidden = (mode === 'here');
    }
    paint();
    modeBox.onclick = function (e)  {
      var b = e.target.closest('[data-m]');
      if (!b) return;
      mode = b.getAttribute('data-m');
      paint();
      if (mode === 'folder') { try { nameInput.focus(); nameInput.select(); } catch (err) { } }
    };
    body.querySelector('#extGo').onclick = function ()  {
      var nm = (nameInput.value || '').trim();
      closeSheet();
      showProgress(T('extract') + '…', null);
      api('extract', { path: item.path, mode: mode, name: mode === 'folder' ? nm : '' }).then(function (res)  {
        hideProgress();
        toast(T('extract') + ' · ' + res.count + ' ' + T('items'));
        refresh();
      }).catch(function (e)  { hideProgress(); toast(e.message, true); });
    };
  }

  /* ---------- 压缩：卡片式对话框 ---------- */
  var cmpPaths = [];
  function openCompressSheet(paths,  defaultName)  {
    cmpPaths = paths || [];
    $('cmpSub').textContent = cmpPaths.length + ' ' + T('items') + ' · ' + T('cmp_save_to') + ' ' + (S.path ? '/' + S.path : '/');
    $('cmpBody').innerHTML =
      '<label class="cmpfield" for="cmpName"><span class="cmplabel">' + esc(T('archive_name')) + '</span>'
      + '<input class="cmpinput" id="cmpName" value="' + esc(defaultName || 'archive') + '" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="120"></label>'
      + '<div class="cmprow">'
      + '<label class="cmpfield" for="cmpFmt"><span class="cmplabel">' + esc(T('zip_format')) + '</span>'
      + '<span class="cmpsel"><select id="cmpFmt"><option value="zip">ZIP</option><option value="tar.gz">TAR.GZ</option></select>'
      + icon('chevron', 'ic') + '</span></label>'
      + '<label class="cmpfield" for="cmpLevel"><span class="cmplabel">' + esc(T('cmp_zip_level')) + '</span>'
      + '<span class="cmpsel"><select id="cmpLevel">'
      + '<option value="6">' + esc(T('cmp_lvl_default')) + '</option>'
      + '<option value="0">' + esc(T('cmp_lvl_store')) + '</option>'
      + '<option value="1">' + esc(T('cmp_lvl_fast')) + '</option>'
      + '<option value="9">' + esc(T('cmp_lvl_best')) + '</option>'
      + '</select>' + icon('chevron', 'ic') + '</span></label>'
      + '</div>'
      + '<div class="cmpcheck" id="cmpCopy" role="checkbox" aria-checked="false" tabindex="0">'
      + '<span class="cmpbox">' + icon('check', 'ic') + '</span>'
      + '<span class="cmptext">' + esc(T('cmp_copy_after')) + '</span></div>';
    $('cmpGo').disabled = false;
    $('cmpDlg').classList.add('on');
    document.body.classList.add('cmp-open');
    openBackdrop();
    function toggleCopy()  {
      var box = $('cmpCopy');
      var on2 = !box.classList.contains('on');
      box.classList.toggle('on', on2);
      box.setAttribute('aria-checked', on2 ? 'true' : 'false');
    }
    on($('cmpCopy'), 'click', toggleCopy);
    on($('cmpCopy'), 'keydown', function (e)  {
      if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggleCopy(); }
    });
    setTimeout(function ()  {
      var inp = $('cmpName');
      if (!inp) return;
      inp.focus();
      var dot = inp.value.lastIndexOf('.');
      try { inp.setSelectionRange(0, dot > 0 ? dot : inp.value.length); } catch (err) {}
    }, 160);
  }
  function closeCompress()  {
    $('cmpDlg').classList.remove('on');
    document.body.classList.remove('cmp-open');
    if (!$('sheet').classList.contains('on') && !$('settingsSheet').classList.contains('on') && !$('dialog').classList.contains('on')) closeBackdrop();
  }
  function submitCompress()  {
    var inp = $('cmpName');
    var name = (inp ? inp.value : '').replace(/[\\/:*?"<>|]/g, '').trim();
    if (!name) { toast(T('cmp_need_name'), true); if (inp) inp.focus(); return; }
    var fmt = $('cmpFmt') ? $('cmpFmt').value : 'zip';
    var level = parseInt($('cmpLevel') ? $('cmpLevel').value : '6', 10);
    if (isNaN(level) || level < 0 || level > 9) level = 6;
    var wantLink = $('cmpCopy') && $('cmpCopy').classList.contains('on');
    var paths = cmpPaths.slice();
    $('cmpGo').disabled = true;
    closeCompress();
    showProgress(T('compress') + '…', null);
    api('compress', { paths: paths, format: fmt, name: name, dest: S.path, level: level }).then(function (res)  {
      hideProgress();
      toast(T('compress') + ' · ' + res.name);
      if (wantLink && res.item) { setTimeout(function ()  { copyLink(res.item); }, 280); }
      exitSelect();
      refresh();
    }).catch(function (e)  { hideProgress(); toast(e.message, true); });
  }

  function showInfo(item)  {
    var base = item || {};
    var body = openSheet(T('info'), base.name);
    body.innerHTML = '<div class="infobox">' + infoRow(T('loading'), '…') + '</div>';
    /* 权限与拥有者不在列表接口里（列表按「显示权限与拥有者」开关才带这两列），
       以前直接拿列表里的那条数据渲染，开关关着就永远是「—」。这里改为打开
       详情时单独请求一次 info 接口，由服务端强制返回权限与拥有者。 */
    if (typeof base.path !== 'string') {
      renderInfo(base);
      return;
    }
    api('info', { path: base.path }, 'GET').then(function (res) {
      renderInfo((res && res.item) ? normalizeItem(res.item) : base);
    }).catch(function () {
      renderInfo(base);
    });
  }
  function renderInfo(item)  {
    var base = item || {};
    var label = typeLabelOf(item);
    var ext = String(item.ext || extOfName(item.name || '')).toLowerCase();
    var editable = !item.dir && isEditable(ext);
    var k = typeKeyOf(item);
    var preview = !item.dir && (k === 'image' || k === 'video' || k === 'audio' || k === 'pdf');
    var chips = '';
    if (ext) chips += '<span class="ftag ftag-mono">.' + esc(ext) + '</span>';
    if (editable) chips += '<span class="ftag ftag-on">' + esc(T('editable')) + '</span>';
    else if (preview) chips += '<span class="ftag">' + esc(T('previewable')) + '</span>';
    var body = openSheet(T('info'), item.name);
    $('sheetHint').textContent = item.name || '';
    var permText = item.perm ? (item.perm + (item.permText ? ' · ' + item.permText : '')) : '—';
    var ownerText = item.owner ? (item.owner + (item.group ? ':' + item.group : '')) : '—';
    /* 文件夹的大小由 info 接口递归统计后返回（列表接口里文件夹 size 恒为 0），
       避免这里仍按旧逻辑写死成「—」 */
    var sizeVal;
    if (item.dir) {
      if (Number(item.subFiles) < 0) {
        /* 无读取权限或统计失败：保持「—」，不要显示成 0 B */
        sizeVal = '—';
      } else {
        var parts = [ (Number(item.sizePartial) ? '≥ ' : '') + (item.sizeText || fmtSize(item.size || 0)) ];
        parts.push(fmtCount(item.subFiles) + ' ' + (T('zip_files') || '个文件'));
        if (Number(item.subDirs) >= 0) parts.push(fmtCount(item.subDirs) + ' ' + (T('zip_folders') || '个文件夹'));
        sizeVal = parts.join(' · ');
        if (Number(item.sizePartial)) sizeVal += ' · ' + (T('stat_partial') || '目录过大，统计已截断');
      }
    } else {
      sizeVal = (item.sizeText || fmtSize(item.size || 0)) + ' (' + Number(item.size || 0) + ' B)';
    }
    body.innerHTML = '<div class="infobox">'
      + infoRow(T('name'), item.name)
      + infoRow(T('size'), sizeVal)
      + infoRow(T('modified'), fmtDate(item.mtime) + ' · ' + new Date(item.mtime * 1000).toLocaleString())
      + infoRowHtml(T('file_kind') || T('type'), '<span class="info-type"><b>' + esc(label) + '</b>' + chips + '</span>')
      + infoRow(T('perm'), permText)
      + infoRow(T('owner'), ownerText)
      + infoRow(T('path'), '/' + item.path)
      + '</div>';
  }
  function infoRow(k,  v)  {
    return '<div class="inforow">'
      + '<span class="ir-k">' + esc(k) + '</span>'
      + '<span class="ir-v">' + esc(v) + '</span></div>';
  }
  function infoRowHtml(k,  v)  {
    return '<div class="inforow">'
      + '<span class="ir-k">' + esc(k) + '</span>'
      + '<span class="ir-v">' + v + '</span></div>';
  }

  /* ============================================================
     5. 预览
     ============================================================ */
  function extOfName(name)  {
    var n = String(name || '').toLowerCase();
    var i = n.lastIndexOf('.');
    return i === -1 ? '' : n.slice(i + 1);
  }
  var MEDIA_EXT = {
    image: ['jpg', 'jpeg', 'jpe', 'jfif', 'pjpeg', 'png', 'apng', 'gif', 'webp', 'bmp', 'dib', 'svg', 'svgz', 'ico', 'cur',
      'avif', 'heic', 'heif', 'tif', 'tiff', 'jxl', 'psd', 'exr', 'hdr', 'raw', 'cr2', 'cr3', 'nef', 'arw', 'dng', 'orf', 'rw2', 'raf', 'sr2'],
    video: ['mp4', 'm4v', 'webm', 'mov', 'qt', 'mkv', 'avi', 'ogv', 'flv', 'f4v', 'wmv', 'asf', '3gp', '3g2', 'mpg',
      'mpeg', 'mpe', 'm1v', 'm2v', 'm2ts', 'mts', 'm3u8', 'm3u', 'rm', 'rmvb', 'divx', 'vob', 'ogm', 'dv', 'h264', 'h265', 'hevc'],
    audio: ['mp3', 'mp2', 'mpga', 'wav', 'wave', 'ogg', 'oga', 'opus', 'flac', 'm4a', 'm4b', 'aac', 'weba', 'wma', 'ape',
      'amr', 'aiff', 'aif', 'aifc', 'au', 'snd', 'mid', 'midi', 'mka', 'ac3', 'dts', 'tak', 'wv', 'tta', 'alac', 'dsf', 'dff', 'ra', 'caf', '3ga']
  };
  function mediaKindOf(name)  {
    var e = extOfName(name);
    if (!e) return '';
    if (MEDIA_EXT.image.indexOf(e) !== -1) return 'image';
    if (MEDIA_EXT.video.indexOf(e) !== -1) return 'video';
    if (MEDIA_EXT.audio.indexOf(e) !== -1) return 'audio';
    return '';
  }
  function isHlsName(name)  {
    var e = extOfName(name);
    return e === 'm3u8' || e === 'm3u';
  }

  /* 预览内的媒体资源句柄：关闭或切换预览时统一释放 */
  var PV = { hls: null };
  function releaseHls()  {
    if (PV.hls)  {
      try  { PV.hls.destroy(); } catch (e)  { }
      PV.hls = null;
    }
  }
  function releaseMedia()  { releaseHls(); }

  function previewFile(item)  {
    if (isZipItem(item)) { openZipViewer(item); return; }
    var v = $('viewer');
    var body = $('vBody');
    body.className = 'v-body';
    $('vName').textContent = item.name;
    $('vMeta').textContent = (item.sizeText || '') + (item.mtime ? ' · ' + fmtDate(item.mtime) : '');
    $('vEdit').style.display = isEditable(item.ext) ? '' : 'none';
    $('vEdit').onclick = function ()  { closeViewer(); openEditor(item); };
    $('vDownload').onclick = function ()  { downloadItem(item); };
    $('vLink').onclick = function ()  { copyLink(item); };
    var url = '?api=raw&path=' + encodeURIComponent(item.path);
    var kind = item.kind;
    if (kind !== 'image' && kind !== 'video' && kind !== 'audio')  {
      kind = mediaKindOf(item.name) || kind;
    }
    releaseMedia();
    body.innerHTML = '';
    if (kind === 'image')  {
      renderImagePreview(body, item, url);
    } else if (kind === 'video')  {
      renderVideoPreview(body, item, url);
    } else if (kind === 'audio')  {
      renderAudioPreview(body, item, url);
    } else if (item.ext === 'pdf')  {
      body.innerHTML = '<iframe src="' + url + '" title="pdf"></iframe>';
    } else if (kind === 'text' || isEditable(item.ext))  {
      body.innerHTML = '<pre style="color:var(--pv-sub)">' + esc(T('loading')) + '</pre>';
      api('read', { path: item.path }, 'GET').then(function (res)  {
        var pre = document.createElement('pre');
        pre.textContent = res.content;
        body.innerHTML = '';
        body.appendChild(pre);
      }).catch(function (e)  {
        body.innerHTML = '<pre style="color:var(--pv-err)">' + esc(e.message) + '</pre>';
      });
    } else  {
      body.innerHTML = '<div style="text-align:center;color:var(--pv-sub)">'
        + '<div style="width:80px;height:80px;margin:0 auto 14px;border-radius:24px;background:var(--pv-chip);display:flex;align-items:center;justify-content:center">' + icon('file', 'ic-lg') + '</div>'
        + '<p style="font-size:13px;margin:0 0 16px">' + esc(T('no_preview') || '这种格式暂不支持在线预览') + '</p>'
        + '<button class="btn btn-primary" style="width:auto;padding:0 20px;margin:0 auto;height:42px" id="pvDl">' + esc(T('download')) + '</button></div>';
      var b = body.querySelector('#pvDl');
      if (b) b.onclick = function ()  { downloadItem(item); };
    }
    v.classList.add('on');
    S.previewItem = item;
  }

  /* ---------- 图片预览：双指缩放 / 双击放大 ---------- */
  function renderImagePreview(body, item, url)  {
    var wrap = document.createElement('div');
    wrap.className = 'pv-imgwrap';
    var img = document.createElement('img');
    img.className = 'pv-img';
    img.alt = item.name;
    img.decoding = 'async';
    wrap.appendChild(img);
    var hint = document.createElement('div');
    hint.className = 'pv-hint';
    hint.textContent = T('pv_zoom_hint');
    wrap.appendChild(hint);
    body.appendChild(wrap);
    img.onerror = function ()  { mediaFallback(body, item, T('pv_fail_image'), 'image'); };
    img.src = url;
    bindImageZoom(wrap, img, hint);
    setTimeout(function ()  { if (hint.parentNode) hint.classList.add('fade'); }, 2800);
  }

  function bindImageZoom(wrap, img, hint)  {
    var scale = 1, tx = 0, ty = 0;
    var pts = {};
    var startDist = 0, startScale = 1, baseX = 0, baseY = 0, px = 0, py = 0, dragging = false, lastTap = 0;
    function count()  { return Object.keys(pts).length; }
    function dist()  {
      var k = Object.keys(pts);
      if (k.length < 2) return 0;
      var a = pts[k[0]], b = pts[k[1]];
      return Math.sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y));
    }
    function clampPan()  {
      var maxX = Math.max(0, (scale - 1) * wrap.clientWidth / 2);
      var maxY = Math.max(0, (scale - 1) * wrap.clientHeight / 2);
      if (tx > maxX) tx = maxX;
      if (tx < -maxX) tx = -maxX;
      if (ty > maxY) ty = maxY;
      if (ty < -maxY) ty = -maxY;
    }
    function apply()  {
      if (scale <= 1.005)  { scale = 1; tx = 0; ty = 0; }
      clampPan();
      img.style.transform = 'translate3d(' + tx.toFixed(2) + 'px,' + ty.toFixed(2) + 'px,0) scale(' + scale.toFixed(3) + ')';
      wrap.classList.toggle('zoomed', scale > 1.01);
      if (scale > 1.01) hint.classList.add('fade');
    }
    on(wrap, 'pointerdown', function (e)  {
      if (e.pointerType === 'mouse' && e.button !== 0) return;
      pts[e.pointerId] = { x: e.clientX, y: e.clientY };
      try  { wrap.setPointerCapture(e.pointerId); } catch (err)  { }
      if (count() === 1)  {
        dragging = true;
        px = e.clientX;
        py = e.clientY;
        baseX = tx;
        baseY = ty;
      } else if (count() === 2)  {
        dragging = false;
        startDist = dist();
        startScale = scale;
      }
    });
    on(wrap, 'pointermove', function (e)  {
      if (!pts[e.pointerId]) return;
      pts[e.pointerId] = { x: e.clientX, y: e.clientY };
      if (count() >= 2 && startDist > 0)  {
        var d = dist();
        if (d > 0)  {
          scale = Math.max(1, Math.min(6, startScale * d / startDist));
          apply();
        }
        if (e.cancelable) e.preventDefault();
      } else if (dragging && scale > 1.01)  {
        tx = baseX + (e.clientX - px);
        ty = baseY + (e.clientY - py);
        wrap.classList.add('dragging');
        apply();
        if (e.cancelable) e.preventDefault();
      }
    });
    function end(e)  {
      delete pts[e.pointerId];
      if (count() < 2) startDist = 0;
      if (count() === 0)  {
        dragging = false;
        wrap.classList.remove('dragging');
      }
    }
    on(wrap, 'pointerup', function (e)  {
      var single = count() === 1;
      end(e);
      if (!single) return;
      var now = Date.now();
      if (now - lastTap < 320)  {
        if (scale > 1.01)  { scale = 1; tx = 0; ty = 0; }
        else  { scale = 2.5; tx = 0; ty = 0; }
        apply();
        lastTap = 0;
      } else  {
        lastTap = now;
      }
    });
    on(wrap, 'pointercancel', end);
  }

  /* ---------- 视频预览：普通视频 + HLS(m3u8) ---------- */
  function renderVideoPreview(body, item, url)  {
    var stage = document.createElement('div');
    stage.className = 'pv-stage';
    var video = document.createElement('video');
    video.className = 'pv-video';
    video.controls = true;
    video.setAttribute('playsinline', '');
    video.setAttribute('webkit-playsinline', '');
    video.setAttribute('preload', 'metadata');
    video.setAttribute('controlslist', 'nodownload');
    stage.appendChild(video);
    body.appendChild(stage);
    var dead = false;
    function fail()  {
      if (dead) return;
      dead = true;
      releaseHls();
      mediaFallback(body, item, T('pv_fail_play'), 'video');
    }
    on(video, 'error', fail);
    if (isHlsName(item.name))  {
      var badge = document.createElement('div');
      badge.className = 'pv-badge';
      badge.textContent = 'HLS';
      stage.appendChild(badge);
      attachHls(video, '?api=hls&path=' + encodeURIComponent(item.path), fail);
    } else  {
      video.src = url;
    }
  }

  /* ---------- 音频预览 ---------- */
  function renderAudioPreview(body, item, url)  {
    var stage = document.createElement('div');
    stage.className = 'pv-audio';
    var disc = document.createElement('div');
    disc.className = 'pv-disc';
    disc.innerHTML = icon('audio', 'ic-lg');
    var title = document.createElement('div');
    title.className = 'pv-atitle';
    title.textContent = item.name;
    var sub = document.createElement('div');
    sub.className = 'pv-asub';
    sub.textContent = (item.sizeText || '') + (item.mtime ? ' · ' + fmtDate(item.mtime) : '')
      + (item.ext ? ' · ' + String(item.ext).toUpperCase() : '');
    var audio = document.createElement('audio');
    audio.controls = true;
    audio.setAttribute('preload', 'metadata');
    audio.setAttribute('controlslist', 'nodownload');
    stage.appendChild(disc);
    stage.appendChild(title);
    stage.appendChild(sub);
    stage.appendChild(audio);
    body.appendChild(stage);
    on(audio, 'play', function ()  { disc.classList.add('spin'); });
    on(audio, 'pause', function ()  { disc.classList.remove('spin'); });
    on(audio, 'ended', function ()  { disc.classList.remove('spin'); });
    on(audio, 'error', function ()  { mediaFallback(body, item, T('pv_fail_play'), 'audio'); });
    audio.src = url;
  }

  /* ---------- 无法播放时的降级面板 ---------- */
  function mediaFallback(body, item, msg, kind)  {
    releaseMedia();
    var ico = kind === 'image' ? 'image' : (kind === 'audio' ? 'audio' : 'video');
    var box = document.createElement('div');
    box.className = 'pv-fail';
    box.innerHTML = '<div class="pv-fail-ico">' + icon(ico, 'ic-lg') + '</div>'
      + '<p class="pv-fail-msg">' + esc(msg) + '</p>'
      + '<p class="pv-fail-tip">' + esc(T('pv_fail_tip')) + '</p>'
      + '<div class="pv-fail-btns">'
      + '<button type="button" class="pv-btn on" id="pvFbDl">' + esc(T('download')) + '</button>'
      + '<button type="button" class="pv-btn" id="pvFbLink">' + esc(T('link')) + '</button>'
      + '</div>';
    body.innerHTML = '';
    body.appendChild(box);
    on($('pvFbDl'), 'click', function ()  { downloadItem(item); });
    on($('pvFbLink'), 'click', function ()  { copyLink(item); });
  }

  /* ---------- HLS：iOS 原生优先，其余浏览器按需加载 hls.js ---------- */
  var HLS_CDN = [
    'https://cdn.jsdelivr.net/npm/hls.js@1.5.20/dist/hls.min.js',
    'https://unpkg.com/hls.js@1.5.20/dist/hls.min.js',
    'https://cdn.staticfile.org/hls.js/1.5.20/hls.min.js'
  ];
  var hlsQueue = null;
  function loadHlsLib(cb)  {
    if (window.Hls)  { cb(true); return; }
    if (hlsQueue)  { hlsQueue.push(cb); return; }
    hlsQueue = [cb];
    var idx = 0;
    function flush(ok)  {
      var list = hlsQueue || [];
      hlsQueue = null;
      for (var i = 0; i < list.length; i++)  {
        try  { list[i](ok); } catch (e)  { }
      }
    }
    function next()  {
      if (window.Hls)  { flush(true); return; }
      if (idx >= HLS_CDN.length)  { flush(false); return; }
      var s = document.createElement('script');
      var done = false;
      var timer = setTimeout(function ()  {
        if (done) return;
        done = true;
        s.onload = null;
        s.onerror = null;
        next();
      }, 8000);
      s.src = HLS_CDN[idx++];
      s.async = true;
      s.onload = function ()  {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (window.Hls) flush(true); else next();
      };
      s.onerror = function ()  {
        if (done) return;
        done = true;
        clearTimeout(timer);
        next();
      };
      document.head.appendChild(s);
    }
    next();
  }

  function attachHls(video, src, onFail)  {
    if (video.canPlayType('application/vnd.apple.mpegurl') || video.canPlayType('application/x-mpegURL'))  {
      video.src = src;
      return;
    }
    loadHlsLib(function (ok)  {
      if (!ok || !window.Hls)  { onFail(); return; }
      var h = null;
      try  {
        h = new window.Hls({ maxBufferLength: 30, enableWorker: true });
      } catch (e)  {
        onFail();
        return;
      }
      var dead = false;
      var retried = 0;
      h.on(window.Hls.Events.ERROR, function (evt, data)  {
        if (dead || !data || !data.fatal) return;
        if (retried < 1 && data.type === window.Hls.ErrorTypes.NETWORK_ERROR)  {
          retried++;
          try  { h.startLoad(); return; } catch (e)  { }
        }
        if (retried < 1 && data.type === window.Hls.ErrorTypes.MEDIA_ERROR)  {
          retried++;
          try  { h.recoverMediaError(); return; } catch (e)  { }
        }
        dead = true;
        try  { h.destroy(); } catch (e)  { }
        PV.hls = null;
        onFail();
      });
      try  {
        h.loadSource(src);
        h.attachMedia(video);
      } catch (e)  {
        dead = true;
        onFail();
        return;
      }
      PV.hls = h;
    });
  }


  /* ---------- ZIP 压缩包内容浏览 ---------- */
  var ZP = { item: null, entries: [], map: {}, tree: {}, total: 0, files: 0, folders: 0,
    bytes: 0, zipSize: 0, truncated: false, path: '', q: '', limit: 220,
    view: null, seq: 0, token: 0, loading: false };

  function isZipItem(item)  { return !!item && !item.dir && /\.zip$/i.test(item.name || ''); }

  function zipExt(name)  {
    var n = String(name || '').toLowerCase();
    var i = n.lastIndexOf('.');
    return i === -1 ? '' : n.slice(i + 1);
  }
  function zipEntryKind(name)  {
    var e = zipExt(name);
    var mk = mediaKindOf(name);
    if (mk) return mk;
    if (e === 'pdf') return 'pdf';
    if (['txt','md','markdown','json','js','mjs','ts','tsx','jsx','css','scss','less','html','htm','xml','yml','yaml','ini','conf','env','log','csv','sql','php','py','sh','java','c','h','cpp','go','rb','rs','vue','lock','toml','gitignore'].indexOf(e) !== -1) return 'text';
    if (e === '') return 'text';
    return 'none';
  }
  function zipEntryIcon(name)  {
    var k = zipEntryKind(name);
    if (k === 'image') return 'image';
    if (k === 'video') return 'video';
    if (k === 'audio') return 'audio';
    if (k === 'pdf') return 'doc';
    if (k === 'text') return 'text';
    if (/\.(zip|rar|7z|gz|tgz|tar|bz2|xz)$/i.test(name || '')) return 'zip';
    return 'file';
  }
  function zipEntryMeta(e)  {
    var meta = fmtSize(e.size || 0) + (e.mtime ? ' · ' + fmtDate(e.mtime) : '');
    if (e.locked) meta += ' · ' + T('zip_encrypted');
    return meta;
  }
  function zipLoadingHTML()  {
    return '<div class="zip-empty"><span class="zip-spin"></span><div>' + esc(T('zip_loading')) + '</div></div>';
  }
  function zipEntryByIndex(i)  { return ZP.map[i] || null; }

  function buildZipTree(entries)  {
    var map = {};
    function ensure(p)  {
      if (!map[p]) map[p] = { dirs: {}, files: [] };
      return map[p];
    }
    ensure('');
    function chain(parts)  {
      var cur = '';
      for (var k = 0; k < parts.length; k++)  {
        var parent = cur;
        cur = cur ? cur + '/' + parts[k] : parts[k];
        ensure(parent).dirs[parts[k]] = cur;
        ensure(cur);
      }
      return cur;
    }
    entries.forEach(function (e)  {
      var name = String(e.name || '').replace(/^\/+|\/+$/g, '');
      if (!name) return;
      var parts = name.split('/');
      if (e.dir)  { chain(parts); return; }
      var dir = chain(parts.slice(0, -1));
      ensure(dir).files.push(e);
    });
    return map;
  }

  function openZipViewer(item)  {
    var v = $('viewer');
    $('vName').textContent = item.name;
    $('vMeta').textContent = (item.sizeText || fmtSize(item.size)) + (item.mtime ? ' · ' + fmtDate(item.mtime) : '');
    $('vEdit').style.display = 'none';
    $('vDownload').onclick = function ()  { downloadItem(item); };
    $('vLink').onclick = function ()  { copyLink(item); };
    ZP = { item: item, entries: [], map: {}, tree: {}, total: 0, files: 0, folders: 0,
      bytes: 0, zipSize: 0, truncated: false, path: '', q: '', limit: 220,
      view: null, seq: ZP.seq + 1, token: 0, loading: true };
    var seq = ZP.seq;
    renderZipShell();
    v.classList.add('on');
    S.previewItem = item;
    api('zip_list', { path: item.path }, 'GET').then(function (res)  {
      if (seq !== ZP.seq) return;
      ZP.entries = res.entries || [];
      ZP.map = {};
      ZP.entries.forEach(function (e)  { ZP.map[e.i] = e; });
      ZP.tree = buildZipTree(ZP.entries);
      ZP.total = res.total || 0;
      ZP.files = res.files || 0;
      ZP.folders = res.folders || 0;
      ZP.bytes = res.bytes || 0;
      ZP.zipSize = res.size || 0;
      ZP.truncated = !!res.truncated;
      ZP.loading = false;
      renderZipStats();
      renderZipCrumbs();
      renderZipList();
    }).catch(function (e)  {
      if (seq !== ZP.seq) return;
      ZP.loading = false;
      var list = $('zipList');
      if (list)  {
        list.innerHTML = '<div class="zip-empty">' + icon('archive') + '<div>' + esc(e.message) + '</div>'
          + '<button type="button" class="zip-btn" id="zipRetry">' + esc(T('refresh')) + '</button></div>';
        var r = $('zipRetry');
        if (r) r.onclick = function ()  { openZipViewer(item); };
      }
    });
  }

  function renderZipShell()  {
    $('vBody').className = 'v-body zip-body';
    $('vBody').innerHTML = '<div class="zipbox">'
      + '<div class="zip-top">'
      + '<div class="zip-stats" id="zipStats"></div>'
      + '<div class="zip-nav">'
      + '<button type="button" class="zip-up" id="zipUp" hidden aria-label="' + esc(T('zip_up')) + '">' + icon('back') + '</button>'
      + '<div class="zip-crumbs" id="zipCrumbs"></div></div>'
      + '<div class="zip-tools"><div class="zip-search">' + icon('search')
      + '<input id="zipSearch" type="search" autocomplete="off" spellcheck="false" placeholder="' + esc(T('zip_search_ph')) + '" value="' + esc(ZP.q) + '">'
      + '<button type="button" class="zip-clear" id="zipClear" aria-label="' + esc(T('close')) + '"' + (ZP.q ? '' : ' hidden') + '>' + icon('close') + '</button>'
      + '</div></div></div>'
      + '<div class="zip-list" id="zipList"></div></div>';
    bindZipShell();
    renderZipStats();
    renderZipCrumbs();
    renderZipList();
  }

  function bindZipShell()  {
    var input = $('zipSearch');
    var timer = 0;
    on(input, 'input', function ()  {
      clearTimeout(timer);
      timer = setTimeout(function ()  {
        ZP.q = String(input.value || '').trim().toLowerCase();
        ZP.limit = 220;
        var clr = $('zipClear');
        if (clr) clr.hidden = !ZP.q;
        renderZipCrumbs();
        renderZipList();
      }, 120);
    });
    on($('zipClear'), 'click', function ()  {
      exitZipSearch();
      input.focus();
    });
    var list = $('zipList');
    on(list, 'click', function (e)  {
      var dl = e.target.closest('.zip-dl');
      if (dl)  {
        e.stopPropagation();
        var de = zipEntryByIndex(Number(dl.getAttribute('data-zdl')));
        if (de) downloadZipEntry(de);
        return;
      }
      var dir = e.target.closest('[data-zdir]');
      if (dir)  { goZipDir(dir.getAttribute('data-zdir')); return; }
      var row = e.target.closest('[data-zi]');
      if (row)  {
        var it = zipEntryByIndex(Number(row.getAttribute('data-zi')));
        if (it) openZipEntry(it);
      }
    });
    /* 面包屑与「上一层」按钮：修复压缩包内无法返回上级目录的问题 */
    var crumbs = $('zipCrumbs');
    on(crumbs, 'click', function (e)  {
      var b = e.target.closest ? e.target.closest('.zip-crumb') : null;
      if (!b || !crumbs.contains(b)) return;
      if (b.hasAttribute('data-zclear'))  { exitZipSearch(); return; }
      var to = b.getAttribute('data-zdir');
      if (to !== null) goZipDir(to);
    });
    on($('zipUp'), 'click', function ()  { zipGoUp(); });
    on(list, 'keydown', function (e)  {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var row = e.target.closest('.zip-row');
      if (!row) return;
      e.preventDefault();
      if (row.hasAttribute('data-zdir')) goZipDir(row.getAttribute('data-zdir'));
      else  {
        var it = zipEntryByIndex(Number(row.getAttribute('data-zi')));
        if (it) openZipEntry(it);
      }
    });
  }

  function goZipDir(path)  {
    path = path || '';
    if (path === ZP.path && !ZP.q)  {
      var same = $('zipList');
      if (same) same.scrollTop = 0;
      return;
    }
    ZP.path = path;
    ZP.q = '';
    ZP.limit = 220;
    var input = $('zipSearch');
    if (input) input.value = '';
    var clr = $('zipClear');
    if (clr) clr.hidden = true;
    renderZipCrumbs();
    renderZipList();
    var list = $('zipList');
    if (list) list.scrollTop = 0;
  }

  /* 退出压缩包内搜索，回到进入搜索前所在的目录 */
  function exitZipSearch()  {
    ZP.q = '';
    ZP.limit = 220;
    var input = $('zipSearch');
    if (input) input.value = '';
    var clr = $('zipClear');
    if (clr) clr.hidden = true;
    renderZipCrumbs();
    renderZipList();
  }

  /* 返回上一层文件夹：搜索状态下先退出搜索，再退到父目录 */
  function zipGoUp()  {
    if (ZP.q)  { exitZipSearch(); return; }
    if (!ZP.path) return;
    goZipDir(parentOf(ZP.path));
  }

  function renderZipStats()  {
    var box = $('zipStats');
    if (!box) return;
    if (ZP.loading)  { box.innerHTML = ''; return; }
    var pct = 0;
    if (ZP.bytes > 0 && ZP.zipSize > 0)  {
      pct = Math.max(0, Math.min(99, Math.round((1 - ZP.zipSize / ZP.bytes) * 100)));
    }
    box.innerHTML = '<span class="zip-chip"><b>' + ZP.files + '</b> ' + esc(T('zip_files')) + '</span>'
      + '<span class="zip-chip"><b>' + ZP.folders + '</b> ' + esc(T('zip_folders')) + '</span>'
      + '<span class="zip-chip">' + esc(T('zip_unpacked')) + ' <b>' + fmtSize(ZP.bytes) + '</b></span>'
      + '<span class="zip-chip">' + esc(T('zip_ratio')) + ' <b>' + pct + '%</b></span>';
  }

  function renderZipCrumbs()  {
    var box = $('zipCrumbs');
    if (!box) return;
    var up = $('zipUp');
    if (up)  {
      up.hidden = !(ZP.path || ZP.q);
      var lbl = ZP.q ? T('zip_exit_search') : T('zip_up');
      up.setAttribute('aria-label', lbl);
      up.setAttribute('title', lbl);
    }
    if (ZP.q)  {
      box.innerHTML = '<button type="button" class="zip-crumb on" data-zclear="1" title="'
        + esc(T('zip_exit_search')) + '">' + esc(T('search')) + ' · ' + esc(ZP.q) + icon('close') + '</button>';
      return;
    }
    var parts = ZP.path ? ZP.path.split('/') : [];
    var html = '<button type="button" class="zip-crumb' + (ZP.path ? '' : ' on') + '" data-zdir=""'
      + (ZP.path ? '' : ' aria-current="true"') + '>' + esc(T('zip_root')) + '</button>';
    var cur = '';
    parts.forEach(function (p)  {
      cur = cur ? cur + '/' + p : p;
      html += '<span class="zip-crumb-sep">/</span><button type="button" class="zip-crumb'
        + (cur === ZP.path ? ' on' : '') + '" data-zdir="' + esc(cur) + '"'
        + (cur === ZP.path ? ' aria-current="true"' : '') + '>' + esc(p) + '</button>';
    });
    box.innerHTML = html;
    box.scrollLeft = box.scrollWidth;
  }

  function renderZipList()  {
    var list = $('zipList');
    if (!list) return;
    if (ZP.loading)  { list.innerHTML = zipLoadingHTML(); return; }
    var dirs = [], files = [];
    if (ZP.q)  {
      ZP.entries.forEach(function (e)  {
        if (String(e.name || '').toLowerCase().indexOf(ZP.q) !== -1)  {
          if (e.dir) dirs.push({ name: baseName(String(e.name).replace(/\/+$/, '')), path: String(e.name).replace(/\/+$/, ''), dir: true });
          else files.push(e);
        }
      });
    } else  {
      var node = ZP.tree[ZP.path] || { dirs: {}, files: [] };
      Object.keys(node.dirs).forEach(function (n)  { dirs.push({ name: n, path: node.dirs[n], dir: true }); });
      files = node.files.slice();
    }
    function cmp(a, b)  { return String(a.name).localeCompare(String(b.name), 'zh-Hans-CN', { numeric: true }); }
    dirs.sort(cmp);
    files.sort(cmp);
    var total = dirs.length + files.length;
    if (!total)  {
      list.innerHTML = '<div class="zip-empty">' + icon('archive') + '<div>'
        + esc(ZP.q ? T('zip_no_match') : T('zip_empty')) + '</div></div>';
      return;
    }
    var html = '';
    if (ZP.truncated && !ZP.q)  {
      html += '<div class="zip-note">' + esc(String(T('zip_truncated')).replace('{n}', String(ZP.entries.length))) + '</div>';
    }
    var shown = 0;
    dirs.forEach(function (d)  {
      if (shown >= ZP.limit) return;
      shown++;
      html += '<div class="zip-row" role="button" tabindex="0" data-zdir="' + esc(d.path) + '">'
        + '<span class="zip-ico dir">' + icon('folder') + '</span>'
        + '<span class="zip-info"><span class="zip-name">' + esc(d.name) + '</span>'
        + '<span class="zip-meta">' + esc(ZP.q ? d.path : T('zip_folders')) + '</span></span>'
        + '<span class="zip-ico" style="background:none">' + icon('chevrond') + '</span></div>';
    });
    files.forEach(function (f)  {
      if (shown >= ZP.limit) return;
      shown++;
      var meta = zipEntryMeta(f);
      if (ZP.q) meta += ' · ' + f.name;
      html += '<div class="zip-row" role="button" tabindex="0" data-zi="' + f.i + '">'
        + '<span class="zip-ico' + (zipEntryKind(f.name) === 'none' ? '' : ' zip') + '">' + icon(zipEntryIcon(f.name)) + '</span>'
        + '<span class="zip-info"><span class="zip-name">' + esc(baseName(f.name)) + '</span>'
        + '<span class="zip-meta">' + esc(meta) + '</span></span>'
        + (f.locked ? '<span class="zip-lock">' + icon('lock') + '</span>'
          : '<button type="button" class="zip-dl" data-zdl="' + f.i + '" aria-label="' + esc(T('zip_entry_dl')) + '">' + icon('download') + '</button>')
        + '</div>';
    });
    var remain = total - shown;
    if (remain > 0)  {
      html += '<div class="zip-more"><button type="button" id="zipMore">' + esc(T('zip_more')) + ' (' + remain + ')</button></div>';
    }
    list.innerHTML = html;
    var more = $('zipMore');
    if (more) more.onclick = function ()  { ZP.limit += 220; renderZipList(); };
  }

  function zipEntryURL(e, dl)  {
    return '?api=zip_raw&path=' + encodeURIComponent(ZP.item.path) + '&i=' + encodeURIComponent(e.i) + (dl ? '&dl=1' : '');
  }
  function downloadZipEntry(e)  {
    var a = document.createElement('a');
    a.href = zipEntryURL(e, true);
    a.setAttribute('download', baseName(e.name));
    document.body.appendChild(a);
    a.click();
    setTimeout(function ()  { if (a.parentNode) a.parentNode.removeChild(a); }, 0);
  }
  function zipEntryFallback(box, e, msg)  {
    if (!box) return;
    box.innerHTML = '<div class="zip-missing">' + icon('file')
      + '<div>' + esc(msg || T('no_preview')) + '</div>'
      + '<button type="button" class="zip-btn" id="zipFbDl">' + esc(T('zip_entry_dl')) + '</button></div>';
    var b = $('zipFbDl');
    if (b) b.onclick = function ()  { downloadZipEntry(e); };
  }

  function openZipEntry(e)  {
    if (e.dir)  { goZipDir(String(e.name).replace(/\/+$/, '')); return; }
    ZP.view = e;
    var token = ++ZP.token;
    var kind = zipEntryKind(e.name);
    $('vBody').innerHTML = '<div class="zip-view">'
      + '<div class="zip-vhead"><button type="button" class="zip-back" id="zipBack" aria-label="' + esc(T('zip_back_list')) + '">' + icon('back') + '</button>'
      + '<div class="zip-vname"><b>' + esc(baseName(e.name)) + '</b><small>' + esc(zipEntryMeta(e)) + '</small></div>'
      + '<button type="button" class="zip-dl" id="zipEntryDl" aria-label="' + esc(T('zip_entry_dl')) + '">' + icon('download') + '</button></div>'
      + '<div class="zip-vbody" id="zipViewBody"></div></div>';
    on($('zipBack'), 'click', backFromZipEntry);
    on($('zipEntryDl'), 'click', function ()  { downloadZipEntry(e); });
    var vb = $('zipViewBody');
    var url = zipEntryURL(e, false);
    if (kind === 'image')  {
      vb.innerHTML = '<img alt="' + esc(baseName(e.name)) + '" src="' + url + '">';
      on(vb.querySelector('img'), 'error', function ()  { zipEntryFallback(vb, e, T('no_preview')); });
    } else if (kind === 'pdf')  {
      vb.innerHTML = '<iframe src="' + url + '" title="pdf"></iframe>';
    } else if (kind === 'video')  {
      if (isHlsName(e.name))  {
        zipEntryFallback(vb, e, T('pv_fail_play'));
        return;
      }
      vb.innerHTML = '<video src="' + url + '" controls playsinline preload="metadata"></video>';
      on(vb.querySelector('video'), 'error', function ()  { zipEntryFallback(vb, e, T('no_preview')); });
    } else if (kind === 'audio')  {
      vb.innerHTML = '<audio src="' + url + '" controls></audio>';
    } else if (kind === 'text')  {
      vb.innerHTML = zipLoadingHTML();
      api('zip_read', { path: ZP.item.path, i: e.i }, 'POST').then(function (res)  {
        if (token !== ZP.token) return;
        var pre = document.createElement('pre');
        pre.className = 'zip-pre';
        pre.textContent = res.content;
        vb.innerHTML = '';
        vb.appendChild(pre);
      }).catch(function (err)  {
        if (token !== ZP.token) return;
        zipEntryFallback(vb, e, err.message);
      });
    } else  {
      zipEntryFallback(vb, e, T('no_preview'));
    }
  }

  function backFromZipEntry()  {
    ZP.view = null;
    ZP.token++;
    renderZipShell();
    var list = $('zipList');
    if (list) list.scrollTop = 0;
  }

  function closeViewer()  {
    $('viewer').classList.remove('on');
    releaseMedia();
    $('vBody').className = 'v-body';
    $('vBody').innerHTML = '';
    ZP.seq++;
    ZP.token++;
    ZP.view = null;
  }

  /* ============================================================
     6. 编辑器
     ============================================================ */
  var ED = {
    item: null, content: '', saved: '', mode: 'normal', ext: '', dirty: false,
    encoding: 'utf-8', saveEncoding: 'utf-8', savedEncoding: 'utf-8', hasBom: false,
    arr: null, lines: 1, maxLen: 0, tier: 0, hlOff: false, loading: false, saving: false,
    lh: 0, padTop: 12, winTop: -1, winBot: -1,
    statsTimer: 0, findTimer: 0, rafId: 0, curRaf: 0, composing: false,
    /* 撤销 / 重做 */
    hist: [], histIdx: -1, histChars: 0, histTimer: 0,
    /* 输入节流 */
    settleTimer: 0, typing: false, typingTimer: 0, liveHl: false
  };

  var KW = {
    js: 'break case catch class const continue debugger default delete do else export extends finally for function if import in instanceof let new return super switch this throw try typeof var void while with yield async await of static get set true false null undefined',
    php: 'abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list namespace new or print private protected public readonly require require_once return static switch throw trait try unset use var while xor yield true false null',
    py: 'and as assert async await break class continue def del elif else except finally for from global if import in is lambda None nonlocal not or pass raise return True False try while with yield self',
    css: 'important media supports keyframes font-face import from to and not only',
    go: 'break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false',
    java: 'abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null',
    sql: 'select from where insert into values update set delete create table drop alter add primary key foreign references join left right inner outer on group by order having limit offset as and or not null distinct union all index default'
  };

  function keywordsFor(ext)  {
    if (['js', 'mjs', 'ts', 'tsx', 'jsx', 'json', 'vue'].indexOf(ext) !== -1) return KW.js;
    if (['php'].indexOf(ext) !== -1) return KW.php;
    if (['py'].indexOf(ext) !== -1) return KW.py;
    if (['css', 'scss', 'less'].indexOf(ext) !== -1) return KW.css;
    if (['go'].indexOf(ext) !== -1) return KW.go;
    if (['java', 'c', 'h', 'cpp', 'rs'].indexOf(ext) !== -1) return KW.java;
    if (['sql'].indexOf(ext) !== -1) return KW.sql;
    return '';
  }

  function highlight(code,  ext)  {
    if (code.length > 200000) return esc(code);
    if (['html', 'htm', 'xml', 'svg', 'vue'].indexOf(ext) !== -1) return hlMarkup(code);
    var kws = keywordsFor(ext);
    var useHash = ['py', 'sh', 'rb', 'yml', 'yaml', 'toml', 'conf', 'ini', 'env', 'gitignore'].indexOf(ext) !== -1;
    var kwPart = kws ? '|\\b(?:' + kws.split(' ').join('|') + ')\\b' : '';
    var re;
    if (useHash) {
      re = new RegExp('(#[^\\n]*)|("""[\\s\\S]*?"""|\'\'\'[\\s\\S]*?\'\'\'|"(?:\\\\.|[^"\\\\\\n])*"|\'(?:\\\\.|[^\'\\\\\\n])*\')|(\\b\\d+(?:\\.\\d+)?\\b)' + kwPart, 'g');
    } else {
      re = new RegExp('(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)|("(?:\\\\.|[^"\\\\\\n])*"|\'(?:\\\\.|[^\'\\\\\\n])*\'|`(?:\\\\.|[^`\\\\])*`)|(\\b\\d+(?:\\.\\d+)?\\b)' + kwPart, 'g');
    }
    var out = '';
    var last = 0;
    var m;
    while ((m = re.exec(code)) !== null) {
      if (m.index > last) out += esc(code.slice(last, m.index));
      var tok = esc(m[0]);
      if (m[2] !== undefined) out += '<span class="tk-str">' + tok + '</span>';
      else if (m[3] !== undefined) out += '<span class="tk-num">' + tok + '</span>';
      else if (m[4] !== undefined) out += '<span class="tk-key">' + tok + '</span>';
      else out += '<span class="tk-com">' + tok + '</span>';
      last = m.index + m[0].length;
      if (m[0].length === 0) re.lastIndex++;
    }
    if (last < code.length) out += esc(code.slice(last));
    return out || ' ';
  }

  function hlMarkup(code)  {
    var esc2 = esc;
    var out = '';
    var re = /(<!--[\s\S]*?-->)|(<\/?[A-Za-z][\w:.-]*)|("[^"\n]*"|'[^'\n]*')|(\s+[A-Za-z_:][\w:.-]*)(?==)|(>)/g;
    var last = 0;
    var m;
    while ((m = re.exec(code)) !== null) {
      if (m.index > last) out += esc2(code.slice(last, m.index));
      if (m[1] !== undefined) out += '<span class="tk-com">' + esc2(m[1]) + '</span>';
      else if (m[2] !== undefined) out += '<span class="tk-tag">' + esc2(m[2]) + '</span>';
      else if (m[3] !== undefined) out += '<span class="tk-str">' + esc2(m[3]) + '</span>';
      else if (m[4] !== undefined) out += '<span class="tk-attr">' + esc2(m[4]) + '</span>';
      else out += '<span class="tk-tag">' + esc2(m[5]) + '</span>';
      last = m.index + m[0].length;
      if (m[0].length === 0) re.lastIndex++;
    }
    if (last < code.length) out += esc2(code.slice(last));
    return out || ' ';
  }

  /* ---------- 编辑器：性能保护（大文件防卡死） ---------- */
  var PERF = (function ()  {
    var coarse = false, mem = 8;
    try { coarse = !!(window.matchMedia && window.matchMedia('(pointer:coarse)').matches); } catch (e1) {}
    try { mem = navigator.deviceMemory || 8; } catch (e2) {}
    var low = coarse || mem <= 4;
    return {
      softSize: low ? 120 * 1024 : 200 * 1024,
      hardSize: low ? 700 * 1024 : 1200 * 1024,
      softLines: low ? 4000 : 6000,
      hardLines: low ? 24000 : 40000
    };
  })();

  function edTier(size,  lines)  {
    if (size > PERF.hardSize || lines > PERF.hardLines) return 2;
    if (size > PERF.softSize || lines > PERF.softLines) return 1;
    return 0;
  }

  function scanText(s)  {
    var arr = (s || '').split('\n');
    var max = 0;
    for (var i = 0, n = arr.length; i < n; i++) { if (arr[i].length > max) max = arr[i].length; }
    return { arr: arr, lines: arr.length, maxLen: max };
  }

  function refreshStats()  {
    var st = scanText(ED.content);
    ED.arr = st.arr;
    ED.lines = st.lines;
    ED.maxLen = st.maxLen;
  }

  function edRaf(fn)  {
    if (window.requestAnimationFrame) { window.requestAnimationFrame(fn); }
    else { setTimeout(fn, 16); }
  }

  /* ---------- 撤销 / 重做：普通与高级编辑器共用一份历史 ---------- */
  var HIST_HARD = 14 * 1024 * 1024;

  function edTA()  { return ED.mode === 'advanced' ? $('advTa') : $('edPlain'); }

  /* 只数换行，不生成行数组：大文件每键调用也只是线性扫描，不产生垃圾对象 */
  function countLines(s)  {
    var n = 1, i = -1;
    while ((i = s.indexOf('\n', i + 1)) !== -1) { n++; }
    return n;
  }

  function histCap()  {
    if (ED.tier >= 2) return 24;
    if (ED.tier === 1) return 40;
    return 80;
  }

  function updateHistButtons()  {
    var u = $('btnUndo'), r = $('btnRedo');
    if (u) u.disabled = !(ED.histIdx > 0);
    if (r) r.disabled = !(ED.histIdx >= 0 && ED.histIdx < ED.hist.length - 1);
  }

  function pushHist(text,  ss,  se)  {
    if (typeof text !== 'string') return;
    if (ED.histIdx >= 0 && ED.hist[ED.histIdx] && ED.hist[ED.histIdx].t === text) {
      var c = ED.hist[ED.histIdx];
      c.s = ss || 0;
      c.e = (se === undefined || se === null) ? c.s : se;
      updateHistButtons();
      return;
    }
    if (ED.histIdx < ED.hist.length - 1) {
      var drop = ED.hist.splice(ED.histIdx + 1);
      for (var i = 0; i < drop.length; i++) { ED.histChars -= drop[i].t.length; }
    }
    ED.hist.push({ t: text, s: ss || 0, e: (se === undefined || se === null) ? (ss || 0) : se });
    ED.histIdx = ED.hist.length - 1;
    ED.histChars += text.length;
    var cap = histCap();
    while (ED.hist.length > cap || (ED.histChars > HIST_HARD && ED.hist.length > 2)) {
      var gone = ED.hist.shift();
      ED.histChars -= gone.t.length;
      ED.histIdx--;
    }
    if (ED.histIdx < 0) { ED.histIdx = 0; }
    updateHistButtons();
  }

  function commitHist()  {
    if (ED.histTimer) { clearTimeout(ED.histTimer); ED.histTimer = 0; }
    var ta = edTA();
    if (!ta || !ED.item) return;
    pushHist(ta.value, ta.selectionStart || 0, ta.selectionEnd || 0);
  }

  function scheduleHist()  {
    if (!ED.item) return;
    if (ED.histTimer) clearTimeout(ED.histTimer);
    ED.histTimer = setTimeout(function ()  {
      ED.histTimer = 0;
      var ta = edTA();
      if (!ta || !ED.item) return;
      pushHist(ta.value, ta.selectionStart || 0, ta.selectionEnd || 0);
    }, 460);
  }

  function lineOfText(text,  pos)  {
    var n = 1, i = -1, lim = Math.min(pos, text.length);
    while ((i = text.indexOf('\n', i + 1)) !== -1 && i < lim) { n++; }
    return n;
  }

  function restoreHist(st)  {
    var ta = edTA();
    if (!ta || !st) return;
    ED.content = st.t;
    if (ta.value !== st.t) { ta.value = st.t; }
    refreshStats();
    markDirty();
    updateEdInfo();
    var s = Math.min(st.s || 0, st.t.length);
    var e = Math.min(st.e === undefined || st.e === null ? s : st.e, st.t.length);
    if (e < s) { e = s; }
    try { ta.setSelectionRange(s, e); } catch (err) { }
    endTyping();
    if (ED.mode === 'advanced') {
      ED.winTop = -1;
      ED.winBot = -1;
      renderAdvanced(true);
      var line = lineOfText(st.t, s);
      var lh = ED.lh || 23;
      var sc = $('advScroll');
      if (ED.wrapMode) {
        try { ta.scrollTop = Math.max(0, (s / Math.max(1, st.t.length)) * ta.scrollHeight - ta.clientHeight / 2); } catch (err2) { }
      } else {
        sc.scrollTop = Math.max(0, (line - 1) * lh - sc.clientHeight / 2);
        renderAdvanced(true);
      }
    } else {
      try { ta.scrollTop = Math.max(0, (lineOfText(st.t, s) - 1) * 23 - ta.clientHeight / 2); } catch (err3) { }
      try { ta.focus({ preventScroll: true }); } catch (err4) { ta.focus(); }
    }
    updateHistButtons();
    queueCursor();
  }

  function edUndo()  {
    if (!ED.item) return;
    var ta = edTA();
    if (!ta) return;
    if (ED.histTimer) { clearTimeout(ED.histTimer); ED.histTimer = 0; }
    if (ED.histIdx < 0) { toast(T('undo_empty')); return; }
    var val = ta.value;
    if (ED.hist[ED.histIdx].t !== val) {
      pushHist(val, ta.selectionStart || 0, ta.selectionEnd || 0);
    }
    if (ED.histIdx <= 0) { toast(T('undo_empty')); return; }
    ED.histIdx--;
    restoreHist(ED.hist[ED.histIdx]);
  }

  function edRedo()  {
    if (!ED.item) return;
    var ta = edTA();
    if (!ta) return;
    if (ED.histTimer) { clearTimeout(ED.histTimer); ED.histTimer = 0; }
    if (ED.histIdx < 0) { toast(T('redo_empty')); return; }
    var val = ta.value;
    if (ED.hist[ED.histIdx].t !== val) {
      pushHist(val, ta.selectionStart || 0, ta.selectionEnd || 0);
    }
    if (ED.histIdx >= ED.hist.length - 1) { toast(T('redo_empty')); return; }
    ED.histIdx++;
    restoreHist(ED.hist[ED.histIdx]);
  }

  /* ---------- 输入节流：打字时不做全文扫描 ---------- */
  function syncAdvHeight()  {
    var ta = $('advTa');
    if (!ta || ED.wrapMode) return;
    if (!ED.lh) edMetrics();
    var docH = Math.round((ED.lines || 1) * (ED.lh || 23) + (ED.padTop || 12) + 64);
    if (ta.style.height !== docH + 'px') ta.style.height = docH + 'px';
    var hlEl = $('hl');
    if (hlEl && hlEl.style.height !== docH + 'px') hlEl.style.height = docH + 'px';
  }

  /* 大文件打字期间交给原生 textarea 上色，停手后再回来铺高亮 */
  function startTyping()  {
    if (ED.mode !== 'advanced' || ED.hlOff) return;
    if (!ED.typing) {
      ED.typing = true;
      $('advTa').classList.add('typing');
      if ($('hl')) { $('hl').style.visibility = 'hidden'; }
    }
    if (ED.typingTimer) clearTimeout(ED.typingTimer);
    ED.typingTimer = setTimeout(function ()  { ED.typingTimer = 0; endTyping(); }, 460);
  }

  function endTyping()  {
    if (ED.typingTimer) { clearTimeout(ED.typingTimer); ED.typingTimer = 0; }
    if (!ED.typing) return;
    ED.typing = false;
    $('advTa').classList.remove('typing');
    if ($('hl') && !ED.hlOff && !ED.composing) { $('hl').style.visibility = ''; }
  }

  function scheduleSettle(ms)  {
    if (ED.settleTimer) clearTimeout(ED.settleTimer);
    ED.settleTimer = setTimeout(function ()  {
      ED.settleTimer = 0;
      if (!ED.item) return;
      var ta = edTA();
      if (!ta) return;
      ED.content = ta.value;
      refreshStats();
      updateEdInfo();
      markDirty();
      endTyping();
      if (ED.mode === 'advanced') { ED.winTop = -1; renderAdvanced(true); }
      queueCursor();
    }, ms || 180);
  }

  function openEditor(item)  {
    if (ED.loading) return;
    ED.loading = true;
    ED.item = null;
    ED.content = '';
    ED.saved = '';
    ED.arr = null;
    ED.dirty = false;
    ED.tier = 0;
    ED.hlOff = false;
    ED.encoding = 'utf-8';
    ED.saveEncoding = 'utf-8';
    ED.savedEncoding = 'utf-8';
    ED.hasBom = false;
    ED.wrapMode = false;
    ED.hlUser = true;
    ED.showGutter = true;
    ED.winTop = -1;
    ED.winBot = -1;
    ED.lh = 0;
    ED.ext = ((item.ext || '') + '').toLowerCase();
    ED.hist = [];
    ED.histIdx = -1;
    ED.histChars = 0;
    ED.typing = false;
    ED.liveHl = false;
    if (ED.histTimer) { clearTimeout(ED.histTimer); ED.histTimer = 0; }
    if (ED.settleTimer) { clearTimeout(ED.settleTimer); ED.settleTimer = 0; }
    if (ED.typingTimer) { clearTimeout(ED.typingTimer); ED.typingTimer = 0; }
    updateHistButtons();

    $('edName').textContent = item.name;
    $('edPath').textContent = '/' + item.path;
    $('edType').textContent = (ED.ext || 'text').toUpperCase();
    $('edInfo').textContent = '—';
    $('edChars').textContent = '0 字符';
    $('edCursor').textContent = '行 1，列 1';
    $('edSave').disabled = true;
    $('edSave').classList.remove('dirty');
    $('edPerf').classList.remove('on');
    $('edPerf').textContent = '';
    $('findBar').classList.remove('on');
    $('hl').style.display = '';
    $('hl').style.visibility = '';
    $('hl').style.transform = 'translateY(0)';
    $('hl').innerHTML = '';
    $('advTa').classList.remove('solid');
    $('advTa').classList.remove('ime');
    $('advTa').classList.remove('typing');
    $('edPlain').value = '';
    $('advTa').value = '';
    resetGutter();
    $('edMask').classList.add('on');
    $('edMaskText').textContent = T('ed_busy');
    $('editor').classList.add('on');
    document.body.style.overflow = 'hidden';

    api('read', { path: item.path }, 'GET').then(function (res)  {
      var content = String(res.content === undefined || res.content === null ? '' : res.content);
      var st = scanText(content);
      ED.item = item;
      ED.content = content;
      ED.saved = content;
      ED.arr = st.arr;
      ED.lines = st.lines;
      ED.maxLen = st.maxLen;
      ED.ext = ((res.ext || item.ext || '') + '').toLowerCase();
      ED.encoding = res.encoding || 'utf-8';
      ED.hasBom = !!res.has_bom;
      ED.saveEncoding = (ED.encoding === 'utf-8' && ED.hasBom) ? 'utf-8bom' : ED.encoding;
      ED.savedEncoding = ED.saveEncoding;
      ED.tier = edTier(content.length, st.lines);
      /* 小文件逐键高亮；中大文件打字期间用原生文字，停手再铺高亮 */
      ED.liveHl = (content.length <= 70000 && st.lines <= 2600);
      ED.hist = [];
      ED.histIdx = -1;
      ED.histChars = 0;
      pushHist(content, 0, 0);
      ED.dirty = false;
      $('edType').textContent = (ED.ext || 'text').toUpperCase();
      $('edName').textContent = item.name;
      updateEncodingLabel();
      $('edSave').disabled = true;
      $('edSave').classList.remove('dirty');

      var mode = (S.settings.editor === 'advanced') ? 'advanced' : 'normal';
      if (ED.tier >= 2) mode = 'normal';
      ED.mode = mode;
      if (mode === 'advanced') { $('advTa').value = content; }
      else { $('edPlain').value = content; }
      resetEditorCaret();
      setMode(mode, true);
      updateEdInfo();
      $('edMask').classList.remove('on');
      ED.loading = false;
      if (ED.tier >= 2) toast(T('ed_tip_huge'));
      else if (ED.tier === 1) toast(T('ed_tip_big'));
      setTimeout(function ()  {
        if (ED.mode === 'advanced') {
          try { $('advTa').focus({ preventScroll: true }); } catch (err) { try { $('advTa').focus(); } catch (e2) {} }
          resetEditorCaret();
          renderAdvanced(true);
        } else {
          try { $('edPlain').focus({ preventScroll: true }); } catch (err2) { $('edPlain').focus(); }
          resetEditorCaret();
        }
        updateCursor();
      }, 120);
    }).catch(function (e)  {
      $('edMask').classList.remove('on');
      ED.loading = false;
      reallyCloseEditor();
      toast(e.message, true);
    });
  }

  function closeEditor()  {
    if (ED.dirty) {
      dialog({
        title: T('unsaved'),
        text: T('close_confirm') || '有未保存的修改，确定关闭吗？',
        input: false,
        okText: T('close'),
        danger: true
      }).then(function (ok)  {
        if (ok) { ED.dirty = false; reallyCloseEditor(); }
      });
      return;
    }
    reallyCloseEditor();
  }

  function reallyCloseEditor()  {
    closeEncoding();
    $('editor').classList.remove('on');
    $('findBar').classList.remove('on');
    document.body.style.overflow = '';
    ED.item = null;
    ED.content = '';
    ED.saved = '';
    ED.arr = null;
    ED.winTop = -1;
    ED.winBot = -1;
    if (ED.statsTimer) { clearTimeout(ED.statsTimer); ED.statsTimer = 0; }
    if (ED.findTimer) { clearTimeout(ED.findTimer); ED.findTimer = 0; }
    if (ED.settleTimer) { clearTimeout(ED.settleTimer); ED.settleTimer = 0; }
    if (ED.histTimer) { clearTimeout(ED.histTimer); ED.histTimer = 0; }
    if (ED.typingTimer) { clearTimeout(ED.typingTimer); ED.typingTimer = 0; }
    ED.typing = false;
    ED.hist = [];
    ED.histIdx = -1;
    ED.histChars = 0;
    $('advTa').classList.remove('typing');
    updateHistButtons();
    $('edMask').classList.remove('on');
    $('hl').innerHTML = '';
  }

  function applyPerfChip()  {
    var chip = $('edPerf');
    var txt = ED.tier >= 2 ? T('ed_perf_huge') : (ED.tier === 1 ? T('ed_perf_big') : '');
    chip.textContent = txt;
    chip.classList.toggle('on', !!txt);
  }

  /* 打开文档时把光标固定在第 1 行第 1 个字符之前，并回到顶部 */
  function resetEditorCaret()  {
    var plain = $('edPlain'), adv = $('advTa');
    try { plain.setSelectionRange(0, 0); } catch (e1) {}
    try { adv.setSelectionRange(0, 0); } catch (e2) {}
    plain.scrollTop = 0;
    plain.scrollLeft = 0;
    adv.scrollTop = 0;
    adv.scrollLeft = 0;
    var sc = $('advScroll');
    if (sc) { sc.scrollTop = 0; sc.scrollLeft = 0; }
    ED.winTop = -1;
    ED.winBot = -1;
  }

  function setMode(mode,  skipSync)  {
    if (!skipSync) { syncContent(); commitHist(); }
    endTyping();
    ED.wrapMode = !!ED.wrapMode;
    ED.mode = mode;
    ED.winTop = -1;
    ED.winBot = -1;
    ED.lh = 0;
    $('paneNormal').classList.toggle('on', mode === 'normal');
    $('paneAdv').classList.toggle('on', mode === 'advanced');
    all('#edModes button').forEach(function (b)  { b.classList.toggle('on', b.getAttribute('data-mode') === mode); });
    if (mode === 'advanced') {
      ED.hlOff = (ED.tier >= 2);
      $('advTa').classList.toggle('solid', ED.hlOff);
      $('advTa').classList.remove('ime');
      $('hl').style.display = ED.hlOff ? 'none' : '';
      $('hl').style.visibility = '';
      if ($('advTa').value !== ED.content) { $('advTa').value = ED.content; }
      $('advTa').scrollTop = 0;
      $('advTa').scrollLeft = 0;
      $('advScroll').scrollTop = 0;
      $('advScroll').scrollLeft = 0;
      applyWrap();
      applyGutter();
      applyHl();
      renderAdvanced(true);
      if (ED.hlOff && !skipSync) toast(T('ed_hl_off'));
      setTimeout(function ()  { try { $('advTa').focus({ preventScroll: true }); } catch (err) { $('advTa').focus(); } }, 30);
    } else {
      if ($('edPlain').value !== ED.content) { $('edPlain').value = ED.content; }
      setTimeout(function ()  { $('edPlain').focus(); }, 30);
    }
    applyPerfChip();
    updateHistButtons();
    saveEditorPref(mode);
  }

  function saveEditorPref(mode)  {
    if (S.settings.editor === mode) return;
    S.settings.editor = mode;
    api('settings_save', buildSettingsPayload({ editor: mode })).catch(function ()  {});
  }

  function syncContent()  {
    if (ED.mode === 'normal') ED.content = $('edPlain').value;
    else ED.content = $('advTa').value;
  }

  function updateEdInfo()  {
    var lines = ED.lines || 1;
    $('edInfo').textContent = lines + ' 行 · ' + ED.content.length + ' 字符';
    $('edChars').textContent = ED.content.length + ' 字符';
  }

  function edMetrics()  {
    /* 行高统一取自 CSS 变量 --ed-lh，行号列与代码正文共用同一个整数像素值，
       避免 1.72 这类小数行高在不同字号下被浏览器分别取整产生的累积错位 */
    var wrap = $('advWrap'), lh = 0;
    if (wrap) lh = parseFloat(window.getComputedStyle(wrap).getPropertyValue('--ed-lh'));
    if (!lh || isNaN(lh)) {
      var cs0 = window.getComputedStyle($('advTa') || $('hl'));
      lh = parseFloat(cs0.lineHeight);
    }
    if (!lh || isNaN(lh)) lh = 23;
    ED.lh = lh;
    var cs = window.getComputedStyle($('advTa') || $('hl'));
    ED.padTop = parseFloat(cs.paddingTop);
    if (isNaN(ED.padTop)) ED.padTop = 12;
  }

  /* 只渲染可视区域：高亮、行号都按窗口绘制，DOM 数量恒定 */
  function renderAdvanced(force)  {
    if (ED.mode !== 'advanced' || !ED.item || ED.wrapMode) return;
    var ta = $('advTa'), sc = $('advScroll');
    if (!ED.lh) edMetrics();
    var lh = ED.lh || 23, pad = ED.padTop || 12;
    var viewH = sc.clientHeight || 360;
    var viewW = sc.clientWidth || 320;
    /* 行数自愈：外部改动、编码转换或异步写入后 ED.lines 可能落后于真实内容 */
    if (force) {
      var real = countLines(ta.value);
      if (real !== ED.lines) { ED.lines = real; ED.arr = null; }
    }
    var total = ED.lines || 1;
    if (viewW < 40) {
      if (!ED.relayout) {
        ED.relayout = 1;
        setTimeout(function ()  { ED.relayout = 0; ED.winTop = -1; renderAdvanced(true); }, 60);
      }
      return;
    }
    var docH = Math.round(total * lh + pad + 64);
    var docW = Math.max(viewW, Math.round((ED.maxLen || 0) * 8.15) + 40);
    if (ta.style.height !== docH + 'px') ta.style.height = docH + 'px';
    if (ta.style.width !== docW + 'px') ta.style.width = docW + 'px';
    var hlEl = $('hl');
    if (hlEl.style.width !== docW + 'px') hlEl.style.width = docW + 'px';
    if (hlEl.style.height !== docH + 'px') hlEl.style.height = docH + 'px';

    var st = sc.scrollTop || 0;
    var first = Math.floor((st - pad) / lh) - 4;
    if (first < 0) first = 0;
    var span = Math.ceil(viewH / lh) + 10;
    var last = first + span;
    if (last > total - 1) last = total - 1;
    if (last < first) last = first;

    if (!force && first === ED.winTop && last === ED.winBot) { paintGutter(first, last, st); return; }
    ED.winTop = first;
    ED.winBot = last;

    if (!ED.hlOff) {
      var arr = ED.arr || [];
      $('hl').style.transform = 'translateY(' + (first * lh) + 'px)';
      $('hl').innerHTML = highlight(arr.slice(first, last + 1).join('\n'), ED.ext) + '\n';
    }
    paintGutter(first, last, st);
  }

  /* 行号：每行一个固定高度的块，逐行定位不依赖字体行盒，
     即使字体晚加载、系统字号放大、滚动到几千行之后也不会累积错位 */
  function paintGutter(first,  last,  st)  {
    var gut = $('gutter'), inner = $('gutIn');
    if (!gut || !inner) return;
    if (!ED.lh) edMetrics();
    var lh = ED.lh, pad = ED.padTop || 12;
    if (last < first) last = first;
    var digits = String(last + 1).length;
    var w = Math.max(46, 22 + Math.round(digits * 7.6));
    if (gut._w !== w) { gut._w = w; gut.style.width = w + 'px'; gut.style.minWidth = w + 'px'; }
    if (gut._f !== first || gut._l !== last) {
      gut._f = first;
      gut._l = last;
      var buf = [];
      for (var i = first; i <= last; i++) buf.push('<span class="gut-ln">' + (i + 1) + '</span>');
      inner.innerHTML = buf.join('');
    }
    var tf = 'translate3d(0,' + (pad + first * lh - st) + 'px,0)';
    if (inner._tf !== tf) { inner._tf = tf; inner.style.transform = tf; }
  }
  function resetGutter()  {
    var gut = $('gutter'), inner = $('gutIn');
    if (gut) { gut._f = gut._l = gut._w = -1; }
    if (inner) { inner._tf = ''; inner.style.transform = ''; }
  }
  /* 字体加载完成 / 旋转屏幕后行高会变，必须重算一次 */
  function remeasureEditor()  {
    if (!ED.item || ED.mode !== 'advanced') return;
    ED.lh = 0;
    ED.winTop = -1;
    ED.winBot = -1;
    resetGutter();
    renderAdvanced(true);
  }

  function queueAdvanced()  {
    if (ED.rafId) return;
    ED.rafId = 1;
    edRaf(function ()  {
      ED.rafId = 0;
      renderAdvanced(false);
    });
  }

  function queueCursor()  {
    if (ED.curRaf) return;
    ED.curRaf = 1;
    edRaf(function ()  {
      ED.curRaf = 0;
      updateCursor();
    });
  }

  function updateCursor()  {
    var ta = activeTA();
    if (!ta || !ED.item) return;
    var text = ta.value;
    var pos = ta.selectionStart || 0;
    if (pos > text.length) pos = text.length;
    var line = 1, lastNl = -1;
    for (var i = 0; i < pos; i++) { if (text.charCodeAt(i) === 10) { line++; lastNl = i; } }
    $('edCursor').textContent = '行 ' + line + '，列 ' + (pos - lastNl);
  }

  function afterInput(ta)  {
    var val = ta.value;
    if (!ED.dirty) {
      ED.dirty = true;
      $('edSave').disabled = false;
      $('edSave').classList.add('dirty');
      $('edName').textContent = (ED.item ? ED.item.name : '') + ' •';
    }
    if (ED.mode === 'advanced') {
      if (!ED.hlOff && ED.liveHl) {
        /* 小文件：可视区域逐键重绘，代价极低 */
        ED.content = val;
        refreshStats();
        updateEdInfo();
        queueAdvanced();
      } else {
        /* 中大文件：只数行号并撑高画布，高亮与统计延迟到停手后 */
        ED.lines = countLines(val);
        syncAdvHeight();
        $('edChars').textContent = val.length + ' 字符';
        $('edInfo').textContent = ED.lines + ' 行 · ' + val.length + ' 字符';
        startTyping();
      }
    } else {
      $('edChars').textContent = val.length + ' 字符';
    }
    queueCursor();
    scheduleSettle(ED.mode === 'advanced' && !ED.liveHl ? 170 : 220);
    scheduleHist();
  }

  function setCompose(on)  {
    ED.composing = on;
    if (ED.mode !== 'advanced' || ED.hlOff) return;
    $('advTa').classList.toggle('ime', on);
    $('hl').style.visibility = on ? 'hidden' : '';
  }

  function guardPaste(e,  ta)  {
    var cd = e.clipboardData || window.clipboardData;
    if (!cd) return;
    var text = '';
    try { text = cd.getData('text/plain') || ''; } catch (err) { return; }
    if (text.length <= 200 * 1024) return;
    e.preventDefault();
    dialog({ title: T('editor'), text: T('ed_paste_big'), input: false }).then(function (ok)  {
      if (!ok) return;
      var s = ta.selectionStart || 0, en = ta.selectionEnd || s;
      var v = ta.value;
      ta.value = v.slice(0, s) + text + v.slice(en);
      ta.setSelectionRange(s + text.length, s + text.length);
      afterInput(ta);
      commitHist();
    });
  }

  function markDirty()  {
    var contentDirty = (ED.content !== ED.saved);
    var encDirty = (ED.saveEncoding !== ED.savedEncoding);
    ED.dirty = contentDirty || encDirty;
    $('edSave').disabled = !ED.dirty;
    $('edSave').classList.toggle('dirty', ED.dirty);
    $('edName').textContent = (ED.item ? ED.item.name : '') + (contentDirty ? ' •' : '');
  }

  function saveFile(force)  {
    if (!ED.item || ED.saving) return;
    if (!ED.dirty && !force) return;
    syncContent();
    commitHist();
    var payload = ED.content;
    var enc = ED.saveEncoding || 'utf-8';
    ED.saving = true;
    var btn = $('edSave');
    btn.disabled = true;
    if (payload.length > 900 * 1024) toast(T('ed_save_big'));
    api('save', { path: ED.item.path, content: payload, encoding: enc, bom: enc === 'utf-8bom' ? '1' : '0' }).then(function (res)  {
      ED.saving = false;
      ED.saved = payload;
      ED.encoding = (res && res.encoding) ? res.encoding : (enc === 'utf-8bom' ? 'utf-8' : enc);
      ED.hasBom = !!(res && res.has_bom);
      ED.savedEncoding = ED.saveEncoding;
      ED.dirty = false;
      btn.disabled = true;
      btn.classList.remove('dirty');
      $('edName').textContent = (ED.item ? ED.item.name : '');
      updateEncodingLabel();
      updateEdInfo();
      closeEncoding();
      toast(T('saved_tip'));
      load(S.path, { view: S.view });
    }).catch(function (e)  {
      ED.saving = false;
      markDirty();
      toast(e.message, true);
    });
  }

  /* ---------- 备份 / 跳转行 / 换行 / 行号 / 高亮 / 编码 ---------- */
  function doBackup()  {
    if (!ED.item || ED.backing) return;
    ED.backing = true;
    syncContent();
    api('backup', { path: ED.item.path, content: ED.content, encoding: ED.encoding || 'utf-8' }).then(function (res)  {
      ED.backing = false;
      toast(T('backup_done') + ' · ' + res.name);
      load(S.path, { view: S.view });
    }).catch(function (e)  { ED.backing = false; toast(e.message, true); });
  }

  function updateEncodingLabel()  {
    var txt = encShort(ED.saveEncoding || 'utf-8');
    if ($('encLabel')) $('encLabel').textContent = txt;
    var chip = $('edEncChip');
    if (chip) {
      chip.textContent = txt;
      chip.classList.toggle('on', !!(ED.saveEncoding && ED.savedEncoding && ED.saveEncoding !== ED.savedEncoding));
      chip.title = T('file_encoding') + ': ' + txt;
    }
  }

  function applyWrap()  {
    var on = !!ED.wrapMode;
    if ($('advWrap')) $('advWrap').classList.toggle('wrapon', on);
    $('edPlain').classList.toggle('wrapon-txt', on);
    $('edPlain').setAttribute('wrap', on ? 'soft' : 'off');
    $('btnWrap').classList.toggle('on', on);
    if ($('btnLn')) $('btnLn').disabled = on && ED.mode === 'advanced';
    if (ED.mode === 'advanced') {
      if (on) { try { $('advTa').scrollTop = 0; $('advTa').scrollLeft = 0; } catch (e) {} }
      else { ED.winTop = -1; ED.lh = 0; renderAdvanced(true); }
    }
  }

  function applyGutter()  {
    if (!$('btnLn')) return;
    var show = ED.showGutter !== false && !ED.wrapMode && ED.mode === 'advanced';
    $('gutter').style.display = (ED.mode === 'advanced' && !ED.wrapMode && ED.showGutter === false) ? 'none' : '';
    $('btnLn').classList.toggle('on', show);
    $('btnLn').disabled = !!ED.wrapMode || ED.mode !== 'advanced';
    if (show) { ED.winTop = -1; renderAdvanced(true); }
  }

  function applyHl()  {
    if (!$('btnHl')) return;
    var off = (ED.tier >= 2) || ED.hlUser === false;
    ED.hlOff = off;
    $('hl').style.display = off ? 'none' : '';
    $('advTa').classList.toggle('solid', off);
    $('btnHl').classList.toggle('on', !off);
    $('btnHl').disabled = ED.tier >= 2 || ED.mode !== 'advanced';
    if (!off) { ED.winTop = -1; renderAdvanced(true); }
  }

  function toggleWrapMode()  {
    ED.wrapMode = !ED.wrapMode;
    applyWrap();
    applyGutter();
    if (ED.mode === 'advanced' && ED.wrapMode) toast(T('wrap'));
  }

  function toggleGutter()  {
    if (ED.mode !== 'advanced') { toast(T('advanced_only'), true); return; }
    if (ED.wrapMode) { toast(T('wrap') + ' · ' + T('line_numbers'), true); return; }
    ED.showGutter = (ED.showGutter === false);
    applyGutter();
  }

  function toggleHl()  {
    if (ED.mode !== 'advanced') { toast(T('advanced_only'), true); return; }
    if (ED.tier >= 2) { toast(T('ed_perf_huge'), true); return; }
    ED.hlUser = (ED.hlUser === false);
    applyHl();
    toast(T('highlight') + ' · ' + (ED.hlUser === false ? T('no') : T('yes')));
  }

  function doGoto()  {
    if (ED.mode !== 'advanced') { toast(T('advanced_only'), true); return; }
    dialog({ title: T('goto_line'), text: '', value: '', placeholder: T('goto_ph'), type: 'number' }).then(function (val)  {
      if (val === null) return;
      var n = parseInt(String(val).replace(/[^0-9]/g, ''), 10);
      var total = ED.lines || 1;
      if (!n || n < 1) return;
      if (n > total) n = total;
      var hay = ED.content, pos = 0, line = 1;
      for (var i = 0; i < hay.length && line < n; i++) {
        if (hay.charCodeAt(i) === 10) { line++; pos = i + 1; }
      }
      var ta = $('advTa');
      try { ta.focus({ preventScroll: true }); } catch (e) { ta.focus(); }
      ta.setSelectionRange(pos, pos);
      if (ED.wrapMode) {
        ta.scrollTop = Math.max(0, (pos / Math.max(1, hay.length)) * (ta.scrollHeight - ta.clientHeight));
      } else {
        var lh = ED.lh || 23;
        $('advScroll').scrollTop = Math.max(0, (n - 1) * lh - $('advScroll').clientHeight / 2);
        queueAdvanced();
      }
      queueCursor();
    });
  }

  /* 编码面板：完全内联在编辑器当前页，不跳转、不打开底部抽屉 */
  var ENC_LIST = [
    { id: 'utf-8', label: 'UTF-8' },
    { id: 'utf-8bom', label: 'UTF-8 BOM' },
    { id: 'gb18030', label: 'GB18030 / GBK' },
    { id: 'big5', label: 'BIG5' },
    { id: 'utf-16le', label: 'UTF-16 LE' },
    { id: 'utf-16be', label: 'UTF-16 BE' }
  ];
  var encTab = 'save';

  function encShort(id)  {
    var map = { 'utf-8': 'UTF-8', 'utf-8bom': 'UTF-8 BOM', 'gb18030': 'GB18030', 'big5': 'BIG5', 'utf-16le': 'UTF-16LE', 'utf-16be': 'UTF-16BE' };
    return map[id] || 'UTF-8';
  }

  function placeEncPop()  {
    var pop = $('encPop'), ed = $('editor'), btn = $('btnEnc');
    if (!pop || !btn) return;
    var er = ed.getBoundingClientRect(), br = btn.getBoundingClientRect();
    var w = pop.offsetWidth || 300, h = pop.offsetHeight || 300;
    var left = br.left - er.left;
    left = Math.max(8, Math.min(left, er.width - w - 8));
    var top = br.bottom - er.top + 6;
    if (top + h > er.height - 8) top = Math.max(8, br.top - er.top - h - 6);
    pop.style.left = left + 'px';
    pop.style.top = top + 'px';
  }

  function openEncoding()  {
    if (!ED.item) return;
    encTab = 'save';
    $('encPop').classList.add('on');
    renderEncPop();
    placeEncPop();
  }

  function closeEncoding()  {
    var pop = $('encPop');
    if (pop) pop.classList.remove('on');
  }

  function renderEncPop()  {
    var pop = $('encPop');
    if (!pop || !pop.classList.contains('on')) return;
    var curSave = ED.saveEncoding || 'utf-8';
    var curRead = ED.encoding || 'utf-8';
    all('#encTabs button').forEach(function (b)  {
      b.classList.toggle('on', b.getAttribute('data-tab') === encTab);
    });
    var list = encTab === 'read' ? ENC_LIST.filter(function (x)  { return x.id !== 'utf-8bom'; }) : ENC_LIST;
    var cur = encTab === 'read' ? curRead : curSave;
    var html = '';
    list.forEach(function (x)  {
      var on = (x.id === cur);
      html += '<button type="button" class="ed-enc-item' + (on ? ' on' : '') + '" data-enc="' + x.id + '">'
        + '<span class="nm">' + esc(x.label) + '</span>'
        + (x.id === 'utf-8bom' ? '<span class="tag">' + esc(T('enc_bom_hint')) + '</span>' : '')
        + '<span class="ck">' + (on ? icon('check', 'ic-sm') : '') + '</span></button>';
    });
    $('encList').innerHTML = html;
    $('encCur').textContent = encTab === 'read' ? encShort(curRead) : encShort(curSave);
    $('encNote').textContent = encTab === 'read' ? T('enc_note_read') : T('enc_note_save');
    var go = $('encApply');
    go.style.display = encTab === 'save' ? '' : 'none';
    go.textContent = T('enc_convert_save') + ' · ' + encShort(curSave);
    go.disabled = (curSave === (ED.savedEncoding || 'utf-8')) && (ED.content === ED.saved);
  }

  function onEncPick(id)  {
    if (encTab === 'read') { applyReadEncoding(id); return; }
    if (id === (ED.saveEncoding || '')) return;
    ED.saveEncoding = id;
    markDirty();
    updateEncodingLabel();
    renderEncPop();
    toast(T('enc_selected') + ' · ' + encShort(id));
  }

  function applyReadEncoding(enc)  {
    if (!ED.item) return;
    var run = function ()  {
      $('edMask').classList.add('on');
      $('edMaskText').textContent = T('ed_busy');
      api('read', { path: ED.item.path, encoding: enc }, 'GET').then(function (res)  {
        var content = String(res.content === undefined || res.content === null ? '' : res.content);
        var st = scanText(content);
        ED.content = content;
        ED.saved = content;
        ED.encoding = res.encoding || enc;
        ED.hasBom = !!res.has_bom;
        ED.saveEncoding = (ED.encoding === 'utf-8' && ED.hasBom) ? 'utf-8bom' : ED.encoding;
        ED.savedEncoding = ED.saveEncoding;
        ED.arr = st.arr;
        ED.lines = st.lines;
        ED.maxLen = st.maxLen;
        ED.tier = edTier(content.length, st.lines);
        ED.dirty = false;
        $('edPlain').value = content;
        $('advTa').value = content;
        resetEditorCaret();
        $('edSave').disabled = true;
        $('edSave').classList.remove('dirty');
        $('edName').textContent = ED.item.name;
        updateEncodingLabel();
        updateEdInfo();
        ED.winTop = -1;
        applyHl();
        renderAdvanced(true);
        $('edMask').classList.remove('on');
        closeEncoding();
        toast(T('enc_read_done') + ' · ' + encShort(ED.encoding));
      }).catch(function (e)  {
        $('edMask').classList.remove('on');
        toast(e.message, true);
      });
    };
    if (ED.content !== ED.saved) {
      dialog({ title: T('file_encoding'), text: T('enc_reload'), input: false }).then(function (ok)  { if (ok) run(); });
    } else { run(); }
  }

  /* ---------- 查找替换 ---------- */
  function toggleFind(force)  {
    var bar = $('findBar');
    var show = force === undefined ? !bar.classList.contains('on') : force;
    bar.classList.toggle('on', show);
    if (show) {
      syncContent();
      $('findInput').focus();
      $('findInput').select();
      scheduleFindCount();
    }
  }
  function activeTA()  { return ED.mode === 'advanced' ? $('advTa') : $('edPlain'); }

  function scheduleFindCount()  {
    if (ED.findTimer) clearTimeout(ED.findTimer);
    ED.findTimer = setTimeout(function ()  { ED.findTimer = 0; updateFindCount(); }, 200);
  }

  function updateFindCount()  {
    var q = $('findInput').value;
    if (!q) { $('findCount').textContent = ''; return; }
    var hay = ED.content, idx = 0, n = 0, cap = 5000, t0 = Date.now(), hit = false;
    while ((idx = hay.indexOf(q, idx)) !== -1) {
      n++;
      idx += q.length;
      if (n >= cap) { hit = true; break; }
      if ((n & 255) === 0 && Date.now() - t0 > 40) { hit = true; break; }
    }
    $('findCount').textContent = (hit ? cap + '+' : n) + ' 处';
  }

  function findNext(dir)  {
    var q = $('findInput').value;
    if (!q) return;
    var ta = activeTA();
    if (!ta) return;
    var from = dir > 0 ? (ta.selectionEnd || 0) : Math.max(0, (ta.selectionStart || 0) - q.length - 1);
    var hay = ED.content;
    var idx = dir > 0 ? hay.indexOf(q, from) : hay.lastIndexOf(q, from);
    if (idx === -1) {
      idx = dir > 0 ? hay.indexOf(q, 0) : hay.lastIndexOf(q, hay.length);
      if (idx === -1) { $('findCount').textContent = '0'; return; }
    }
    ta.focus();
    ta.setSelectionRange(idx, idx + q.length);
    if (ED.mode === 'advanced') {
      var line = 1;
      for (var i = 0; i < idx; i++) { if (hay.charCodeAt(i) === 10) line++; }
      var lh = ED.lh || 23;
      $('advScroll').scrollTop = Math.max(0, line * lh - $('advScroll').clientHeight / 2);
      queueAdvanced();
    }
    scheduleFindCount();
  }

  function replaceOne()  {
    var q = $('findInput').value;
    var rep = $('replaceInput').value;
    if (!q) return;
    var ta = activeTA();
    if (!ta) return;
    var sel = ED.content.slice(ta.selectionStart, ta.selectionEnd);
    if (sel === q) {
      var next = ED.content.slice(0, ta.selectionStart) + rep + ED.content.slice(ta.selectionEnd);
      var pos = ta.selectionStart + rep.length;
      applyContent(next);
      ta.setSelectionRange(pos, pos);
    }
    findNext(1);
  }

  function replaceAll()  {
    var q = $('findInput').value;
    if (!q) return;
    var rep = $('replaceInput').value;
    var run = function ()  {
      var hay = ED.content, from = 0, idx = 0, count = 0, out = '';
      while ((idx = hay.indexOf(q, from)) !== -1) {
        out += hay.slice(from, idx) + rep;
        from = idx + q.length;
        count++;
      }
      out += hay.slice(from);
      applyContent(out);
      toast((T('replace_all') || '替换') + ' · ' + count);
      scheduleFindCount();
    };
    if (ED.content.length > 400 * 1024) {
      dialog({ title: T('replace_all'), text: T('ed_paste_big'), input: false }).then(function (ok)  { if (ok) run(); });
      return;
    }
    run();
  }

  function applyContent(next)  {
    var ta0 = edTA();
    if (ta0) { pushHist(ta0.value, ta0.selectionStart || 0, ta0.selectionEnd || 0); }
    ED.content = next;
    if (ED.mode === 'advanced') { $('advTa').value = next; }
    else { $('edPlain').value = next; }
    refreshStats();
    markDirty();
    updateEdInfo();
    if (ED.mode === 'advanced') { ED.winTop = -1; renderAdvanced(true); }
    var ta1 = edTA();
    if (ta1) { pushHist(next, ta1.selectionStart || 0, ta1.selectionEnd || 0); }
    queueCursor();
  }

  /* ---------- 编辑器键盘 ---------- */
  function bindEditorKeys(ta)  {
    on(ta, 'keydown', function (e)  {
      var meta = e.metaKey || e.ctrlKey;
      var k = (e.key || '').toLowerCase();
      if (meta && k === 's') { e.preventDefault(); saveFile(); return; }
      if (meta && k === 'f') { e.preventDefault(); toggleFind(true); return; }
      if (meta && k === 'z') { e.preventDefault(); if (e.shiftKey) { edRedo(); } else { edUndo(); } return; }
      if (meta && k === 'y') { e.preventDefault(); edRedo(); return; }
      if (e.key === 'Escape') {
        if ($('encPop') && $('encPop').classList.contains('on')) { closeEncoding(); }
        else if ($('findBar').classList.contains('on')) { toggleFind(false); }
        else { closeEditor(); }
        return;
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        var start = ta.selectionStart, end = ta.selectionEnd, value = ta.value;
        if (start !== end && value.slice(start, end).indexOf('\n') !== -1) {
          var lineStart = value.lastIndexOf('\n', start - 1) + 1;
          var seg = value.slice(lineStart, end);
          var shifted = seg.split('\n').map(function (l)  {
            if (e.shiftKey) return l.replace(/^ {2}/, '');
            return '  ' + l;
          }).join('\n');
          ta.value = value.slice(0, lineStart) + shifted + value.slice(end);
          ta.setSelectionRange(lineStart, lineStart + shifted.length);
        } else {
          var ins = '  ';
          ta.value = value.slice(0, start) + ins + value.slice(end);
          ta.setSelectionRange(start + ins.length, start + ins.length);
        }
        afterInput(ta);
        commitHist();
        queueCursor();
      }
    });
    on(ta, 'keyup', queueCursor);
    on(ta, 'click', queueCursor);
    on(ta, 'select', queueCursor);
  }

  function bindEditing(ta)  {
    on(ta, 'compositionstart', function ()  { setCompose(true); });
    on(ta, 'compositionend', function ()  { setCompose(false); afterInput(ta); });
    on(ta, 'input', function ()  { if (ED.composing) return; afterInput(ta); });
    on(ta, 'paste', function (e)  { guardPaste(e, ta); });
  }

  bindEditing($('edPlain'));
  bindEditing($('advTa'));
  bindEditorKeys($('edPlain'));
  bindEditorKeys($('advTa'));
  on($('advScroll'), 'scroll', function ()  { queueAdvanced(); });
  on($('advTa'), 'scroll', function ()  { queueAdvanced(); });
  on($('advTa'), 'focus', function ()  { queueCursor(); });
  on($('edPerf'), 'click', function ()  { if (ED.tier) toast(T('ed_perf_tip')); });
  /* 屏幕旋转 / 字体晚到 / 可视高度变化：重新测行高并重绘行号，杜绝半截行号 */
  on(window, 'orientationchange', function ()  { setTimeout(remeasureEditor, 260); });
  on(window, 'resize', function ()  { if (ED.resizeT) clearTimeout(ED.resizeT); ED.resizeT = setTimeout(remeasureEditor, 180); });
  if (window.ResizeObserver && $('advScroll')) {
    try {
      ED.ro = new ResizeObserver(function ()  {
        if (ED.mode !== 'advanced' || !ED.item) return;
        if (ED.roT) clearTimeout(ED.roT);
        ED.roT = setTimeout(function ()  { ED.winTop = -1; ED.winBot = -1; renderAdvanced(true); }, 60);
      });
      ED.ro.observe($('advScroll'));
    } catch (eRo) {}
  }
  if (document.fonts && document.fonts.ready && document.fonts.ready.then) {
    try {
      document.fonts.ready.then(function ()  { setTimeout(remeasureEditor, 30); });
    } catch (eFont) {}
  }
  all('#edModes button').forEach(function (b)  {
    on(b, 'click', function ()  { setMode(b.getAttribute('data-mode')); });
  });
  on($('edSave'), 'click', saveFile);
  on($('edClose'), 'click', closeEditor);
  on($('edFind'), 'click', function ()  { toggleFind(); });
  on($('findNext'), 'click', function ()  { findNext(1); });
  on($('findPrev'), 'click', function ()  { findNext(-1); });
  on($('findInput'), 'input', scheduleFindCount);
  on($('findInput'), 'keydown', function (e)  { if (e.key === 'Enter') { e.preventDefault(); findNext(e.shiftKey ? -1 : 1); } });
  on($('replaceOne'), 'click', replaceOne);
  on($('replaceAll'), 'click', replaceAll);
  on($('findClose'), 'click', function ()  { toggleFind(false); });
  on($('btnBackup'), 'click', doBackup);
  on($('btnGoto'), 'click', doGoto);
  on($('btnWrap'), 'click', toggleWrapMode);
  on($('btnLn'), 'click', toggleGutter);
  on($('btnHl'), 'click', toggleHl);
  on($('btnEnc'), 'click', openEncoding);
  on($('edEncChip'), 'click', openEncoding);
  on($('encX'), 'click', closeEncoding);
  on($('encApply'), 'click', function ()  { saveFile(true); });
  on($('encTabs'), 'click', function (e)  {
    var b = e.target.closest('[data-tab]');
    if (!b) return;
    encTab = b.getAttribute('data-tab');
    renderEncPop();
  });
  on($('encList'), 'click', function (e)  {
    var b = e.target.closest('[data-enc]');
    if (!b) return;
    onEncPick(b.getAttribute('data-enc'));
  });
  on(document, 'click', function (e)  {
    var pop = $('encPop');
    if (!pop || !pop.classList.contains('on')) return;
    var t = e.target;
    if (!t || !t.closest) return;
    if (t.closest('#encPop') || t.closest('#btnEnc') || t.closest('#edEncChip')) return;
    closeEncoding();
  });

  var edResizeTimer = 0;
  on(window, 'resize', function ()  {
    if (!ED.item || ED.mode !== 'advanced') return;
    if (edResizeTimer) clearTimeout(edResizeTimer);
    edResizeTimer = setTimeout(function ()  {
      edResizeTimer = 0;
      ED.lh = 0;
      ED.winTop = -1;
      ED.winBot = -1;
      renderAdvanced(true);
    }, 180);
    if ($('encPop') && $('encPop').classList.contains('on')) placeEncPop();
  });

  /* ============================================================
     7. 上传 / URL / GitHub
     ============================================================ */
  function uploadFiles(files,  rels)  {
    if (!files || !files.length) return;
    var fd = new FormData();
    fd.append('path', S.path);
    for (var i = 0; i < files.length; i++) {
      fd.append('files[]', files[i]);
      fd.append('rels[]', rels && rels[i] ? rels[i] : '');
    }
    var xhr = new XMLHttpRequest();
    var total = 0;
    for (var j = 0; j < files.length; j++) total += files[j].size || 0;
    showProgress(T('uploading') + ' ' + files.length + ' ' + T('items'), 0);
    xhr.open('POST', '?api=upload', true);
    xhr.setRequestHeader('X-CSRF-Token', BOOT.csrf || '');
    xhr.setRequestHeader('X-Lang', S.lang);
    xhr.upload.onprogress = function (e)  {
      if (e.lengthComputable) showProgress(T('uploading') + ' ' + files.length + ' ' + T('items'), e.loaded / e.total * 100);
    };
    xhr.onload = function ()  {
      hideProgress();
      var res = null;
      try { res = JSON.parse(xhr.responseText); } catch (err) {}
      if (res && res.ok) {
        toast(T('upload_done') + ' · ' + (res.saved || []).length);
        if (res.failed && res.failed.length) toast(res.failed.join('、'), true);
        refresh();
      } else {
        toast((res && res.error) || '上传失败', true);
      }
    };
    xhr.onerror = function ()  { hideProgress(); toast(T('err_net'), true); };
    xhr.send(fd);
  }

  function bindUpload()  {
    on($('fileInput'), 'change', function ()  {
      uploadFiles(this.files, null);
      this.value = '';
    });
    on($('folderInput'), 'change', function ()  {
      var files = Array.prototype.slice.call(this.files);
      var rels = files.map(function (f)  { return f.webkitRelativePath || f.name; });
      uploadFiles(files, rels);
      this.value = '';
    });
  }

  function openUrlSheet()  {
    var body = openSheet(T('url_dl'), T('url_hint'));
    body.innerHTML = '<div class="formlabel">URL</div>'
      + '<div class="fieldrow"><input id="urlInput" type="url" inputmode="url" placeholder="https://example.com/file.zip" spellcheck="false" autocomplete="off"></div>'
      + '<div class="formlabel">' + esc(T('file_name')) + '</div>'
      + '<div class="fieldrow"><input id="urlName" placeholder="' + esc(T('optional') || '留空则自动识别') + '" spellcheck="false"></div>'
      + '<div style="font-size:11.5px;color:var(--text-3);line-height:1.6;margin:2px 2px 14px">' + esc(T('url_hint')) + '</div>'
      + '<button class="btn btn-primary dlbtn" id="urlGo">' + icon('download', 'ic-sm') + esc(T('download')) + '</button>';
    setTimeout(function ()  { body.querySelector('#urlInput').focus(); }, 200);
    on(body.querySelector('#urlGo'), 'click', function ()  {
      var url = body.querySelector('#urlInput').value.trim();
      var name = body.querySelector('#urlName').value.trim();
      if (!/^https?:\/\//i.test(url)) { toast('请输入 http/https 链接', true); return; }
      closeSheet();
      showProgress(T('download_start') + '…', null);
      api('url_download', { url: url, name: name, path: S.path }, 'POST').then(function (res)  {
        hideProgress();
        toast(T('download') + ' · ' + res.name);
        refresh();
      }).catch(function (e)  { hideProgress(); toast(e.message, true); });
    });
  }

  function ghDate(v)  {
    if (!v) return '';
    var d = new Date(v);
    if (isNaN(d.getTime())) return '';
    var m = d.getMonth() + 1, day = d.getDate();
    return d.getFullYear() + '-' + (m < 10 ? '0' + m : m) + '-' + (day < 10 ? '0' + day : day);
  }

  function ghNum(n)  {
    n = Number(n) || 0;
    if (n >= 10000) {
      return S.lang === 'en' ? (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k'
        : (n / 10000).toFixed(1).replace(/\.0$/, '') + '万';
    }
    if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(n);
  }

  function ghLink(url)  {
    return /^https:\/\/github\.com\//i.test(url || '') ? url : '';
  }

  function openGithubSheet()  {
    var body = openSheet(T('github_dl'), 'owner/repo');
    var last = localStorage.getItem('xiazzi.repo') || '';
    body.innerHTML = '<div class="formlabel">' + esc(T('github_repo')) + '</div>'
      + '<div class="fieldrow"><input id="ghRepo" value="' + esc(last) + '" placeholder="owner/repo" spellcheck="false" autocomplete="off">'
      + '<button class="btn btn-ghost" id="ghLoad" style="height:44px">' + esc(T('github_load')) + '</button></div>'
      + '<div class="ghcard" id="ghLead"><div class="ghc-t">' + icon('info', 'ic') + esc(T('gh_intro')) + '</div>'
      + '<ul class="ghsteps">'
      + '<li><i>1</i><span>' + esc(T('gh_howto_1')) + '</span></li>'
      + '<li><i>2</i><span>' + esc(T('gh_howto_2')) + '</span></li>'
      + '<li><i>3</i><span>' + esc(T('gh_howto_3')) + '</span></li>'
      + '</ul></div><div id="ghResult"></div>';
    setTimeout(function ()  { var r = body.querySelector('#ghRepo'); if (r) r.focus(); }, 200);

    var box = body.querySelector('#ghResult');
    var state = { repo: '', ref: '', kind: 'branch', item: null, versions: [], mode: 'zip' };

    /* zip 直存时预览的文件名，与后端保持一致：仓库名-版本 */
    function ghBaseName()  {
      var repo = String(state.repo || '').split('/');
      var name = repo[1] || repo[0] || 'repo';
      var ref = String(state.ref || '').replace(/[^A-Za-z0-9._-]/g, '-');
      return name + (ref ? '-' + ref : '');
    }

    /* 下载方式统一由「设置 · 通用」决定：默认仅下载 zip，不自动解压 */
    function wantExtract()  {
      return !!(S.settings && S.settings.gh_extract);
    }

    function syncMode()  {
      var useExtract = wantExtract();
      state.mode = useExtract ? 'extract' : 'zip';
      var ic = box.querySelector('#ghModeIcon');
      if (ic) ic.innerHTML = icon(useExtract ? 'unzip' : 'zip', 'ic');
      var name = box.querySelector('#ghModeName');
      if (name) name.textContent = useExtract ? T('gh_mode_extract') : T('gh_mode_zip');
      var note = box.querySelector('#ghPickNote');
      if (note) {
        var base = ghBaseName();
        note.textContent = (useExtract ? T('gh_will_extract') : T('gh_will_zip'))
          .replace('{name}', useExtract ? base + '/' : base + '.zip');
      }
      var lbl = box.querySelector('#ghGoLabel');
      if (lbl) lbl.textContent = useExtract ? T('github_dl_btn') : T('github_dl_zip_btn');
    }

    function renderDetail()  {
      var d = box.querySelector('#ghDetail');
      if (!d) return;
      var it = state.item;
      if (!it) {
        d.hidden = true;
        d.innerHTML = '';
        return;
      }
      d.hidden = false;
      var isTag = it.kind === 'tag';
      var url = ghLink(it.url);
      var note = it.note || (isTag ? T('gh_no_note') : T('gh_branch_note'));
      var meta = [];
      if (it.date) meta.push(T('gh_updated') + ' ' + ghDate(it.date));
      meta.push(isTag ? (it.has_rel ? T('gh_rel_notes') : T('gh_tag_note')) : T('gh_branches_n'));
      if (it.pre) meta.push(T('gh_pre'));
      if (it.zip) meta.push(T('gh_zip_size') + ': ' + fmtSize(it.zip));
      d.innerHTML = '<div class="gd-h"><b>' + esc(it.ref) + '</b><em>' + esc(isTag ? 'tag' : 'branch') + '</em>'
        + (url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener">' + esc(T('gh_view')) + icon('external', 'ic') + '</a>' : '')
        + '</div><div class="gd-m">' + esc(meta.join(' · ')) + '</div>'
        + '<p>' + esc(note) + '</p>';
    }

    function renderList()  {
      var list = box.querySelector('#ghList');
      if (!list) return;
      var html = '';
      state.versions.forEach(function (v,  i)  {
        var on = (v.ref === state.ref && v.kind === state.kind);
        var sub = (v.zip ? T('gh_zip_size') + ': ' + fmtSize(v.zip) + ' · ' : '') + (v.date ? ghDate(v.date) + ' · ' : '') + (v.note || (v.kind === 'tag' ? T('gh_no_note') : T('gh_branch_note')));
        html += '<button class="ghver' + (on ? ' on' : '') + '" data-i="' + i + '">'
          + '<span class="gv-main"><span class="gv-n"><span>' + esc(v.ref) + '</span>'
          + (v.def ? '<em>' + esc(T('github_default')) + '</em>' : '')
          + (v.pre ? '<em>' + esc(T('gh_pre')) + '</em>' : '') + '</span>'
          + '<span class="gv-d">' + esc(sub) + '</span></span>'
          + '<span class="gv-b">' + esc(v.kind === 'tag' ? 'tag' : 'branch') + '</span></button>';
      });
      list.innerHTML = html;
      list.querySelectorAll('.ghver').forEach(function (b)  {
        b.addEventListener('click', function ()  {
          var v = state.versions[Number(b.getAttribute('data-i'))];
          if (!v) return;
          state.ref = v.ref;
          state.kind = v.kind;
          state.item = v;
          list.querySelectorAll('.ghver').forEach(function (x)  { x.classList.remove('on'); });
          b.classList.add('on');
          renderDetail();
          syncMode();
        });
      });
    }

    function loadRefs()  {
      var repo = body.querySelector('#ghRepo').value.trim();
      if (!repo) { toast(T('github_ph'), true); return; }
      box.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-3);font-size:12.5px">' + esc(T('loading')) + '</div>';
      api('github_refs', { repo: repo }).then(function (res)  {
        var lead = body.querySelector('#ghLead');
        if (lead) lead.style.display = 'none';
        localStorage.setItem('xiazzi.repo', res.repo);
        state.repo = res.repo;
        var def = res.default || 'main';
        var versions = [];
        versions.push({ ref: def, kind: 'branch', def: true, date: res.updated || '', zip: res.zip_size || 0, note: T('gh_default_note') });
        (res.branches || []).forEach(function (b)  {
          if (b.name === def) return;
          versions.push({ ref: b.name, kind: 'branch', date: b.date || '', zip: b.zip_size || res.zip_size || 0, note: b.note || T('gh_branch_note') });
        });
        (res.tags || []).forEach(function (t)  {
          versions.push({
            ref: t.name, kind: 'tag', date: t.date || '', zip: t.zip_size || res.zip_size || 0, url: t.url || '',
            pre: !!t.pre, has_rel: !!t.has_rel, note: t.note || ''
          });
        });
        state.versions = versions;
        state.ref = def;
        state.kind = 'branch';
        state.item = versions[0];

        var chips = [];
        if (res.lang) chips.push(icon('code', 'ic') + '<b>' + esc(res.lang) + '</b>');
        if (res.license) chips.push(icon('shield', 'ic') + esc(res.license));
        chips.push(icon('star', 'ic') + ghNum(res.stars));
        chips.push('Fork ' + ghNum(res.forks));
        if (res.updated) chips.push(icon('clock', 'ic') + ghDate(res.updated));
        if (res.archived) chips.push(esc(T('gh_archived')));
        if (res.zip_size) chips.push(icon('zip', 'ic') + T('gh_zip_size') + ': ' + fmtSize(res.zip_size));
        (res.topics || []).forEach(function (t)  { chips.push('#' + esc(t)); });

        var head = '<div class="ghhead"><div class="ghi">' + icon('github', 'ic-sm') + '</div>'
          + '<div class="ght"><b>' + esc(res.repo) + '</b>'
          + '<small>' + esc(res.desc || T('gh_no_desc')) + '</small></div>'
          + '<span class="ghbadge ' + (res.private ? 'warn' : 'good') + '">' + (res.private ? 'PRIVATE' : 'PUBLIC') + '</span></div>';

        var sum = '<div class="ghsum"><span>' + esc(T('gh_summary')
          .replace('{b}', String((versions.filter(function (v)  { return v.kind === 'branch'; })).length))
          .replace('{t}', String((res.tags || []).length))) + '</span>';
        if (res.latest && res.latest.tag) {
          sum += '<span class="dot"></span><b>' + esc(T('gh_latest')) + '</b><span>' + esc(res.latest.tag)
            + (res.latest.date ? ' · ' + ghDate(res.latest.date) : '') + '</span>';
        }
        sum += '</div>';

        var intro = res.intro || res.desc || T('gh_no_desc');
        box.innerHTML = head
          + '<div class="ghcard"><div class="ghc-t">' + icon('info', 'ic') + esc(T('gh_intro')) + '</div>'
          + '<p>' + esc(intro) + '</p>'
          + (chips.length ? '<div class="ghchips"><span>' + chips.join('</span><span>') + '</span></div>' : '')
          + '</div>'
          + sum
          + '<div class="ghverbox" id="ghList"></div>'
          + '<div class="ghdetail" id="ghDetail" hidden></div>'
          + '<div class="gh-dlbar">'
          + '<button type="button" class="ghmode" id="ghModeInfo" aria-label="' + esc(T('gh_dl_mode')) + '">'
          + '<span class="gm-ic" id="ghModeIcon">' + icon('zip', 'ic') + '</span>'
          + '<span class="gm-tx"><b id="ghModeName"></b><small id="ghPickNote"></small></span>'
          + '<span class="gm-go">' + esc(T('gh_change_mode')) + '</span></button>'
          + '<button class="btn btn-primary dlbtn" id="ghGo">' + icon('download', 'ic-sm')
          + '<span id="ghGoLabel"></span></button></div>';

        renderList();
        renderDetail();
        syncMode();
        on(box.querySelector('#ghModeInfo'), 'click', function ()  {
          closeSheet();
          setTimeout(function ()  { openSettings('general'); }, 60);
        });
        on(box.querySelector('#ghGo'), 'click', function ()  {
          var mode = wantExtract() ? 'extract' : 'zip';
          closeSheet();
          showProgress(T('github_dl') + ' · ' + state.repo + (mode === 'zip' ? ' · zip' : ''), null);
          api('github_download', { repo: state.repo, ref: state.ref, kind: state.kind, path: S.path, mode: mode }, 'POST').then(function (r)  {
            hideProgress();
            if (r && r.extracted) {
              toast(T('github_done') + ' · ' + r.name);
            } else {
              toast(T('gh_saved_zip') + ' · ' + (r.file || r.name));
            }
            refresh();
          }).catch(function (e)  { hideProgress(); toast(e.message, true); });
        });
      }).catch(function (e)  {
        box.innerHTML = '<div class="notice" style="margin:10px 0">' + esc(e.message) + '</div>';
      });
    }

    on(body.querySelector('#ghLoad'), 'click', loadRefs);
    on(body.querySelector('#ghRepo'), 'keydown', function (e)  { if (e.key === 'Enter') loadRefs(); });
  }

  /* ============================================================
     8. 设置
     ============================================================ */
  function buildSettingsPayload(patch)  {
    var base = {
      lang: S.settings.lang || S.lang,
      theme: S.settings.theme || 'system',
      editor: S.settings.editor || 'normal',
      show_hidden: !!S.settings.show_hidden,
      show_perms: !!S.settings.show_perms,
      hide_self: !!S.settings.hide_self,
      gh_extract: !!S.settings.gh_extract,
      link_style: S.settings.link_style === 'param' ? 'param' : 'pretty'
    };
    if (patch) Object.keys(patch).forEach(function (k)  { base[k] = patch[k]; });
    return base;
  }
  function saveSettings(patch,  silent)  {
    return api('settings_save', buildSettingsPayload(patch)).then(function (res)  {
      S.settings = res.settings;
      if (patch && patch.lang) S.lang = patch.lang;
      applyTheme();
      applyI18n();
      if (!silent) toast(T('token_saved'));
      renderChips();
      syncNav();
      updateTitle();
      render();
      if ($('settingsSheet').classList.contains('on')) { syncTabs(); renderSettings(); }
      if (S.view === 'files') load(S.path);
      return res.settings;
    }).catch(function (e)  { toast(e.message, true); });
  }

  /* 修改用户名/密码成功后：立即登出并回到登录页 */
  function forceRelogin(msg)  {
    closeSettings();
    if ($('sheet').classList.contains('on')) closeSheet();
    dialog({ title: T('settings_security'), text: esc(msg), input: false, single: true, okText: T('login_again') }).then(function ()  {
      location.href = location.pathname;
    });
  }

  var currentSTab = 'general';
  function openSettings(tab)  {
    currentSTab = tab || 'general';
    $('settingsSheet').classList.add('on');
    document.body.classList.add('sheet-open');
    openBackdrop();
    renderSettings();
    all('#settingsTabs button').forEach(function (b)  { b.classList.toggle('on', b.getAttribute('data-stab') === currentSTab); });
    syncNav();
  }
  function closeSettings()  {
    $('settingsSheet').classList.remove('on');
    if (!$('sheet').classList.contains('on') && !$('dialog').classList.contains('on')) {
      closeBackdrop();
      document.body.classList.remove('sheet-open');
    }
    syncNav();
  }

  function dirRuleBlock(s)  {
    if (s.link_style === 'param') return '';
    var name = s.script_name || 'index.php';
    var rule = 'RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^(.+)/$ ' + name + '?p=$1 [L,QSA]';
    return '<div style="font-size:11.5px;color:var(--text-3);line-height:1.6;margin-bottom:16px">'
      + esc(T('dir_rule_hint'))
      + '<pre style="margin:8px 0 0;padding:10px 12px;border-radius:12px;background:var(--surface-2);border:1px solid var(--line);color:var(--text-2);font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-all;overflow-x:auto">'
      + esc(rule) + '</pre></div>';
  }

  function renderSettings()  {
    var body = $('settingsBody');
    var s = S.settings;
    $('settingsHint').textContent = '';
    if (currentSTab === 'general') {
      body.innerHTML =
        '<div class="setstore" id="setStoreCard" hidden>'
        + '<div class="setstore-top"><div><div class="setstore-label">' + esc(T('storage')) + '</div>'
        + '<div class="setstore-value" id="setStoreFree">—<small>' + esc(T('free')) + '</small></div></div></div>'
        + '<div class="setstore-bar"><i id="setStoreBar" style="width:0%"></i></div>'
        + '<div class="setstore-foot"><span id="setStoreUsed">—</span><span id="setStoreTotal">—</span></div>'
        + '<div class="setstore-path">' + icon('folder', 'ic-sm') + '<b id="setStorePath">—</b></div>'
        + '</div>'
        + '<div class="formlabel">' + esc(T('language')) + '</div>'
        + '<div class="langgrid" id="setLang" style="margin-bottom:14px">'
        + '<button data-lang="zh-CN" class="' + (S.lang === 'zh-CN' ? 'on' : '') + '">简体中文</button>'
        + '<button data-lang="zh-TW" class="' + (S.lang === 'zh-TW' ? 'on' : '') + '">繁體中文</button>'
        + '<button data-lang="en" class="' + (S.lang === 'en' ? 'on' : '') + '">English</button>'
        + '<button data-lang="ja" class="' + (S.lang === 'ja' ? 'on' : '') + '">日本語</button>'
        + '<button data-lang="ko" class="' + (S.lang === 'ko' ? 'on' : '') + '">한국어</button>'
        + '<button data-lang="es" class="' + (S.lang === 'es' ? 'on' : '') + '">Español</button></div>'
        + '<div class="formlabel">' + esc(T('theme')) + '</div>'
        + '<div class="segmented" id="setTheme" style="margin-bottom:14px">'
        + '<button data-theme="system" class="' + (s.theme === 'system' ? 'on' : '') + '">' + esc(T('theme_system')) + '</button>'
        + '<button data-theme="light" class="' + (s.theme === 'light' ? 'on' : '') + '">' + esc(T('theme_light')) + '</button>'
        + '<button data-theme="dark" class="' + (s.theme === 'dark' ? 'on' : '') + '">' + esc(T('theme_dark')) + '</button></div>'
        + '<div class="formlabel">' + esc(T('default_editor')) + '</div>'
        + '<div class="segmented" id="setEditor" style="margin-bottom:16px">'
        + '<button data-editor="normal" class="' + (s.editor === 'normal' ? 'on' : '') + '">' + esc(T('editor_normal')) + '</button>'
        + '<button data-editor="advanced" class="' + (s.editor === 'advanced' ? 'on' : '') + '">' + esc(T('editor_adv')) + '</button></div>'
        + '<div class="sgroup">'
        + srow('eye', T('show_hidden'), T('show_hidden_hint') || '显示以点开头的隐藏文件与目录', 'switch', !!s.show_hidden, 'show_hidden')
        + srow('shield', T('show_perms'), T('show_perms_hint') || '列表与详情中显示 chmod 权限及拥有者', 'switch', !!s.show_perms, 'show_perms')
        + srow('lock', T('hide_self'), T('hide_self_hint') || '在列表中隐藏本程序文件（设置已内嵌其中）', 'switch', !!s.hide_self, 'hide_self')
        + '</div>'
        + '<div class="formlabel">' + esc(T('link_style')) + '</div>'
        + '<div class="segmented" id="setLinkStyle" style="margin-bottom:8px">'
        + '<button data-ls="pretty" class="' + (s.link_style !== 'param' ? 'on' : '') + '">' + icon('link', 'ic-sm') + esc(T('link_style_pretty')) + '</button>'
        + '<button data-ls="param" class="' + (s.link_style === 'param' ? 'on' : '') + '">' + icon('code', 'ic-sm') + esc(T('link_style_param')) + '</button></div>'
        + '<div style="font-size:11.5px;color:var(--text-3);line-height:1.6;margin-bottom:8px">' + esc(T('link_style_hint')) + '</div>'
        + '<div style="margin-bottom:12px;padding:10px 12px;border-radius:12px;background:var(--surface-2);border:1px solid var(--line);font-size:11.5px;line-height:2;color:var(--text-3);word-break:break-all">'
        + '<div><span style="display:inline-block;min-width:72px">' + esc(T('link_sample_file')) + '</span><b style="color:var(--text-2);font-weight:600">' + esc(s.link_sample_file || '—') + '</b></div>'
        + '<div><span style="display:inline-block;min-width:72px">' + esc(T('link_sample_dir')) + '</span><b style="color:var(--text-2);font-weight:600">' + esc(s.link_sample_dir || '—') + '</b></div>'
        + '</div>'
        + dirRuleBlock(s)
        + '<div class="formlabel">' + esc(T('gh_dl_mode')) + '</div>'
        + '<div class="segmented" id="setGhMode" style="margin-bottom:8px">'
        + '<button data-gh="zip" class="' + (!s.gh_extract ? 'on' : '') + '">' + icon('zip', 'ic-sm') + esc(T('gh_mode_zip')) + '</button>'
        + '<button data-gh="extract" class="' + (s.gh_extract ? 'on' : '') + '">' + icon('unzip', 'ic-sm') + esc(T('gh_mode_extract')) + '</button></div>'
        + '<div style="font-size:11.5px;color:var(--text-3);line-height:1.6;margin-bottom:16px">' + esc(T('gh_dl_mode_hint')) + '</div>'
        + '<div class="formlabel">' + esc(T('github_token')) + '</div>'
        + '<div class="fieldrow"><input id="setToken" type="password" placeholder="' + (s.has_token ? '••••••••' : 'ghp_…') + '" spellcheck="false" autocomplete="off">'
        + '<button class="btn btn-ghost" id="tokenSave" style="height:44px">' + esc(T('save')) + '</button></div>'
        + '<div style="font-size:11.5px;color:var(--text-3);line-height:1.6">' + esc(T('github_token_hint')) + '</div>';

      bindSettingClicks(body);
      paintStorage();
      var ts = body.querySelector('#tokenSave');
      if (ts) ts.onclick = function ()  {
        var v = body.querySelector('#setToken').value.trim();
        if (!v) { toast(T('github_token') + ' · —', true); return; }
        saveSettings({ gh_token: v }).then(function ()  { body.querySelector('#setToken').value = ''; });
      };
    } else if (currentSTab === 'security') {
      body.innerHTML =
        '<div class="sgroup">'
        + srow('user', T('user'), '', 'value', false, '', esc(BOOT.user))
        + srow('shield', T('settings_security'), T('two_step_hint') || '修改密码后需要重新登录', 'value', false, '', T('good'))
        + '</div>'
        + '<div class="formlabel">' + esc(T('change_user')) + '</div>'
        + '<div class="secbox">'
        + '<input class="secfield" id="unNew" type="text" placeholder="' + esc(T('new_user')) + '" autocomplete="username" spellcheck="false">'
        + '<input class="secfield" id="unPass" type="password" placeholder="' + esc(T('old_pass')) + '" autocomplete="current-password">'
        + '<button class="btn btn-primary seccenter" id="unGo">' + icon('user', 'ic-sm') + esc(T('change_user')) + '</button>'
        + '</div>'
        + '<div class="formlabel">' + esc(T('change_pass')) + '</div>'
        + '<div class="secbox">'
        + '<input class="secfield" id="pwOld" type="password" placeholder="' + esc(T('old_pass')) + '" autocomplete="current-password">'
        + '<input class="secfield" id="pwNew" type="password" placeholder="' + esc(T('new_pass')) + '" autocomplete="new-password">'
        + '<input class="secfield" id="pwNew2" type="password" placeholder="' + esc(T('confirm_pass')) + '" autocomplete="new-password">'
        + '<div class="hint" id="pwHint" style="font-size:11.5px;color:var(--danger);min-height:16px;margin:0 2px"></div>'
        + '<button class="btn btn-primary seccenter" id="pwGo">' + icon('lock', 'ic-sm') + esc(T('change_pass')) + '</button>'
        + '<div class="sechint">' + esc(T('pass_store_hint')) + '</div>'
        + '</div>'
        + '<div class="secbox" style="margin-top:20px">'
        + '<button class="btn btn-ghost seccenter" id="doLogout" style="color:var(--danger)">' + icon('logout', 'ic-sm') + esc(T('sign_out')) + '</button>'
        + '<div class="sechint">' + esc(T('session_hint') || '会话保存在服务器，退出后需重新输入密码') + '</div>'
        + '</div>';

      on(body.querySelector('#unGo'), 'click', function ()  {
        var u = body.querySelector('#unNew').value.trim();
        var p1 = body.querySelector('#unPass').value;
        if (!u) { toast(T('new_user'), true); return; }
        if (u === BOOT.user) { toast(T('new_user') + ' · ' + u, true); return; }
        api('username', { user: u, pass: p1 }).then(function (res)  {
          if (res && res.logout) { forceRelogin(T('cred_user_out')); return; }
          BOOT.user = res.user;
          if (S.settings) S.settings.user = res.user;
          toast(T('user_changed') + ' · ' + res.user);
          renderSettings();
        }).catch(function (e)  { toast(e.message, true); });
      });
      on(body.querySelector('#pwGo'), 'click', function ()  {
        var oldV = body.querySelector('#pwOld').value;
        var n1 = body.querySelector('#pwNew').value;
        var n2 = body.querySelector('#pwNew2').value;
        var hint = body.querySelector('#pwHint');
        hint.textContent = '';
        if (n1.length < 6) { hint.textContent = T('pass_short'); return; }
        if (n1 !== n2) { hint.textContent = T('pass_mismatch'); return; }
        api('password', { old: oldV, new: n1 }).then(function (res)  {
          if (res && res.logout) { forceRelogin(T('cred_pass_out')); return; }
          toast(T('pass_changed'));
          body.querySelector('#pwOld').value = '';
          body.querySelector('#pwNew').value = '';
          body.querySelector('#pwNew2').value = '';
        }).catch(function (e)  { hint.textContent = e.message; });
      });
      on(body.querySelector('#doLogout'), 'click', function ()  {
        dialog({ title: T('sign_out'), text: T('sign_out_confirm') || '确定退出登录吗？', input: false, danger: true, okText: T('sign_out') }).then(function (ok)  {
          if (!ok) return;
          api('logout', {}).then(function ()  { location.href = location.pathname; }).catch(function ()  { location.reload(); });
        });
      });
    } else if (currentSTab === 'env') {
      body.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;padding:2px 2px 8px">'
        + '<span style="font-size:12px;color:var(--text-3)">PHP ' + esc(BOOT.php || '') + '</span>'
        + '<button class="sortbtn" id="envRefresh">' + icon('refresh', 'ic-sm') + esc(T('env_recheck')) + '</button></div>'
        + '<div id="envList" style="background:var(--surface-2);border:1px solid var(--line);border-radius:16px;padding:4px 12px">'
        + '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:12.5px">' + esc(T('loading')) + '</div></div>';
      on(body.querySelector('#envRefresh'), 'click', loadEnv);
      loadEnv();
    } else {
      body.innerHTML = '<div class="about-hero">'
        + '<div class="am" role="img" aria-label="Eu"><i>Eu</i></div>'
        + '<h3>' + esc(BOOT.title) + '</h3>'
        + '<p>' + esc(T('about_text')) + '</p>'
        + '<div class="ver">' + esc(BOOT.version) + '</div></div>'
        + '<div class="about-list">'
        + '<div><span>' + esc(T('version')) + '</span><b>' + esc(BOOT.version) + '</b></div>'
        + '<div><span>PHP</span><b>' + esc(BOOT.php) + '</b></div>'
        + (BOOT.storage && Number(BOOT.storage.known) ? '<div><span>' + esc(T('total')) + '</span><b>' + esc(BOOT.storage.totalText) + '</b></div>' : '')
        + '<div><span>' + esc(T('root')) + '</span><b>' + esc(BOOT.rootName) + '</b></div>'
        + '<div><span>' + esc(T('copyright')) + '</span><b>© ' + esc(BOOT.year) + ' 冰虾数据</b></div>'
        + '<div><span>' + esc(T('license')) + '</span><b>MIT</b></div>'
        + '</div>'
        + '<div class="about-foot">'
        + '<span class="af-rule"></span>'
        + '<div class="af-copy">Copyright ©' + esc(BOOT.year) + ' 冰虾数据 All Rights Reserved</div>'
        + '<div class="af-line">易优PHP管理器,由[冰虾数据],用AI程序编写生成</div>'
        + '<div class="af-line">有疑问请邮箱联系「<a class="af-mail" href="mailto:adminx@bingxia.email.cn">adminx@bingxia.email.cn</a>」</div>'
        + '</div>';
    }
  }

  function srow(iconName,  title,  hint,  type,  onState,  key,  valueText)  {
    var right = '';
    if (type === 'switch') right = '<span class="switch ' + (onState ? 'on' : '') + '" data-sw="' + key + '"></span>';
    else right = '<span class="sval">' + esc(valueText || '') + '</span>';
    return '<div class="srow"><span class="si">' + icon(iconName, 'ic-sm') + '</span>'
      + '<span class="stx"><b>' + esc(title) + '</b>' + (hint ? '<small>' + esc(hint) + '</small>' : '') + '</span>'
      + right + '</div>';
  }

  function bindSettingClicks(body)  {
    var langBox = body.querySelector('#setLang');
    if (langBox) on(langBox, 'click', function (e)  {
      var b = e.target.closest('[data-lang]');
      if (!b) return;
      var lang = b.getAttribute('data-lang');
      if (lang === S.lang) return;
      S.lang = lang;
      saveSettings({ lang: lang });
    });
    var themeBox = body.querySelector('#setTheme');
    if (themeBox) on(themeBox, 'click', function (e)  {
      var b = e.target.closest('[data-theme]');
      if (!b) return;
      saveSettings({ theme: b.getAttribute('data-theme') });
      all('#setTheme button', body).forEach(function (x)  { x.classList.toggle('on', x === b); });
    });
    var edBox = body.querySelector('#setEditor');
    if (edBox) on(edBox, 'click', function (e)  {
      var b = e.target.closest('[data-editor]');
      if (!b) return;
      saveSettings({ editor: b.getAttribute('data-editor') });
      all('#setEditor button', body).forEach(function (x)  { x.classList.toggle('on', x === b); });
    });
    var ghBox = body.querySelector('#setGhMode');
    if (ghBox) on(ghBox, 'click', function (e)  {
      var b = e.target.closest('[data-gh]');
      if (!b) return;
      var wantExtract = b.getAttribute('data-gh') === 'extract';
      if (!!S.settings.gh_extract === wantExtract) return;
      all('#setGhMode button', body).forEach(function (x)  { x.classList.toggle('on', x === b); });
      saveSettings({ gh_extract: wantExtract }, true).then(function ()  {
        if (S.settings.gh_extract !== wantExtract) { renderSettings(); }
      });
    });
    var lsBox = body.querySelector('#setLinkStyle');
    if (lsBox) on(lsBox, 'click', function (e)  {
      var b = e.target.closest('[data-ls]');
      if (!b) return;
      var style = b.getAttribute('data-ls');
      if ((S.settings.link_style || 'pretty') === style) return;
      all('#setLinkStyle button', body).forEach(function (x)  { x.classList.toggle('on', x === b); });
      saveSettings({ link_style: style }, true).then(function ()  {
        if ((S.settings.link_style || 'pretty') !== style) { renderSettings(); }
      });
    });
    all('[data-sw]', body).forEach(function (sw)  {
      on(sw, 'click', function ()  {
        var key = sw.getAttribute('data-sw');
        var next = !sw.classList.contains('on');
        sw.classList.toggle('on', next);
        var patch = {};
        patch[key] = next;
        saveSettings(patch, true);
      });
    });
  }

  function loadEnv()  {
    var box = $('envList');
    if (!box) return;
    api('env', {}, 'GET').then(function (res)  {
      box.innerHTML = (res.rows || []).map(function (r)  {
        return '<div class="envrow"><div class="el">' + esc(r.label) + (r.hint ? '<small>' + esc(r.hint) + '</small>' : '') + '</div>'
          + '<div class="ev">' + esc(r.value) + '</div>'
          + '<span class="es ' + esc(r.state) + '">' + esc(T(r.state === 'good' ? 'good' : (r.state === 'warn' ? 'warn' : 'bad'))) + '</span></div>';
      }).join('');
    }).catch(function (e)  {
      box.innerHTML = '<div class="notice" style="margin:8px 0">' + esc(e.message) + '</div>';
    });
  }
  function syncTabs()  {
    all('#settingsTabs button').forEach(function (b)  { b.classList.toggle('on', b.getAttribute('data-stab') === currentSTab); });
  }

  /* ============================================================
     9. 交互绑定
     ============================================================ */
  function switchView(view)  {
    if (view === 'settings') { openSettings('general'); return; }
    if (S.selecting) exitSelect();
    if (view === S.view && view !== 'files') { load(S.path, { view: view }); return; }
    load(S.path, { view: view });
  }

  function bindAll()  {
    all('.nav-item').forEach(function (b)  {
      on(b, 'click', function ()  { switchView(b.getAttribute('data-view')); });
    });
    all('.tab').forEach(function (b)  {
      on(b, 'click', function ()  { switchView(b.getAttribute('data-view')); });
    });
    on($('btnBack'), 'click', function ()  {
      if (S.view !== 'files') { load(S.path, { view: 'files' }); return; }
      if (S.path) load(parentOf(S.path), { view: 'files' });
    });
    on($('btnSelect'), 'click', function ()  {
      if (S.selecting) exitSelect();
      else enterSelect('');
    });
    on($('btnSelAll'), 'click', selectAll);
    on($('btnSelInvert'), 'click', invertSelect);
    on($('btnSelDone'), 'click', exitSelect);

    on($('btnSearch'), 'click', openSearch);
    on($('btnSearchClose'), 'click', closeSearch);
    on($('btnSearchClear'), 'click', function ()  { $('searchInput').value = ''; $('searchInput').focus(); refresh(); });
    on($('searchInput'), 'input', function ()  {
      var v = this.value;
      clearTimeout(searchTimer);
      searchTimer = setTimeout(function ()  { doSearch(v); }, 320);
    });
    on($('searchInput'), 'keydown', function (e)  {
      if (e.key === 'Enter') { clearTimeout(searchTimer); doSearch(this.value); this.blur(); }
      if (e.key === 'Escape') closeSearch();
    });

    on($('chips'), 'click', function (e)  {
      var b = e.target.closest('[data-kind]');
      if (!b) return;
      S.kind = b.getAttribute('data-kind');
      renderChips();
      render();
      $('scroll').scrollTo({ top: 0, behavior: 'smooth' });
    });

    on($('btnSort'), 'click', openSortSheet);
    on($('thName'), 'click', function ()  { setSort('name'); });
    on($('thSize'), 'click', function ()  { setSort('size'); });
    on($('thTime'), 'click', function ()  { setSort('time'); });
    on($('thPerm'), 'click', function ()  { setSort('type'); });

    on($('btnViewList'), 'click', function ()  { setViewMode('list'); });
    on($('btnViewGrid'), 'click', function ()  { setViewMode('grid'); });

    on($('emptyBtn'), 'click', function ()  { $('fileInput').click(); });

    on($('fab'), 'click', openCreateSheet);

    on($('btnMore'), 'click', openMainMenu);

    on($('selActions'), 'click', function (e)  {
      var b = e.target.closest('[data-sel]');
      if (!b || b.disabled) return;
      handleBatch(b.getAttribute('data-sel'));
    });

    on($('btnPaste'), 'click', function ()  { pasteInto(S.path); });
    on($('btnClipClear'), 'click', clearClipboard);

    on($('sheetClose'), 'click', closeSheet);
    on($('cmpCancel'), 'click', closeCompress);
    on($('cmpGo'), 'click', submitCompress);
    on($('cmpBody'), 'keydown', function (e)  {
      if (e.key === 'Enter' && e.target && e.target.id === 'cmpName') { e.preventDefault(); submitCompress(); }
    });
    on($('settingsClose'), 'click', closeSettings);
    on(backdrop, 'click', function ()  {
      if ($('dialog').classList.contains('on')) return;
      if ($('cmpDlg').classList.contains('on')) { closeCompress(); return; }
      closeSheet();
      closeSettings();
    });
    on($('settingsTabs'), 'click', function (e)  {
      var b = e.target.closest('[data-stab]');
      if (!b) return;
      currentSTab = b.getAttribute('data-stab');
      syncTabs();
      renderSettings();
    });

    on($('vClose'), 'click', closeViewer);
    on($('viewer'), 'click', function (e)  { if (e.target === $('vBody') || e.target === $('viewer')) closeViewer(); });

    var fabDimTimer = 0;
    on($('scroll'), 'scroll', function ()  {
      var t = this.scrollTop;
      $('topbar').classList.toggle('scrolled', t > 4);
      /* 滚动时让悬浮按钮收缩淡出，停手后再恢复，避免挡住掠过区域 */
      var fab = $('fab');
      if (fab) {
        fab.classList.add('dim');
        clearTimeout(fabDimTimer);
        fabDimTimer = setTimeout(function ()  { fab.classList.remove('dim'); }, 520);
      }
    }, { passive: true });

    document.addEventListener('keydown', function (e)  {
      var tag = (document.activeElement && document.activeElement.tagName) || '';
      var typing = /INPUT|TEXTAREA/.test(tag);
      if (e.key === 'Escape') {
        if ($('editor').classList.contains('on')) return;
        if ($('viewer').classList.contains('on')) { closeViewer(); return; }
        if ($('dialog').classList.contains('on')) { dlgDone(null); return; }
        if ($('cmpDlg').classList.contains('on')) { closeCompress(); return; }
        if ($('sheet').classList.contains('on')) { closeSheet(); return; }
        if ($('settingsSheet').classList.contains('on')) { closeSettings(); return; }
        if ($('searchBar').classList.contains('on')) { closeSearch(); return; }
        if (S.selecting) exitSelect();
      }
      if (typing) return;
      if (e.key === 'Delete' && S.selecting) {
        var items = selectedItems();
        doDelete(selectedPaths(), items.map(function (i)  { return i.name; }));
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'a' && S.selecting) {
        e.preventDefault();
        selectAll();
      }
    });

    bindList();
    bindUpload();
  }

  function openMainMenu()  {
    var body = openSheet(T('more'), S.path ? '/' + S.path : T('root'));
    var items = [
      { act: 'newfolder', icon: 'folderplus', label: T('new_folder'), color: 'orange' },
      { act: 'newfile', icon: 'fileplus', label: T('new_file'), color: 'green' },
      { act: 'upload', icon: 'upload', label: T('upload'), color: 'blue' },
      { act: 'uploadfolder', icon: 'cloud', label: T('upload_folder'), color: 'teal' },
      { act: 'url', icon: 'link', label: T('url_dl'), color: 'violet' },
      { act: 'github', icon: 'github', label: T('github_dl'), color: 'dark' },
      { act: 'select', icon: 'selectall', label: T('select'), color: 'gray' }
    ];
    if (S.clip) items.push({ act: 'paste', icon: 'paste', label: T('paste_here'), color: 'amber' });
    items.push({ act: 'refresh', icon: 'refresh', label: T('refresh') || '刷新', color: 'slate' });
    items.push({ act: 'settings', icon: 'settings', label: T('settings'), color: 'gray' });
    items.push({ act: 'logout', icon: 'logout', label: T('logout'), danger: true });
    body.innerHTML = tileMenu(items);
    bindSheetActions(body, function (act)  {
      closeSheet();
      setTimeout(function ()  {
        if (act === 'newfolder') newFolder();
        else if (act === 'newfile') newFile();
        else if (act === 'upload') $('fileInput').click();
        else if (act === 'uploadfolder') $('folderInput').click();
        else if (act === 'url') openUrlSheet();
        else if (act === 'github') openGithubSheet();
        else if (act === 'select') enterSelect('');
        else if (act === 'paste') pasteInto(S.path);
        else if (act === 'refresh') refresh();
        else if (act === 'settings') openSettings('general');
        else if (act === 'logout') doLogout();
      }, 40);
    });
  }

  function doLogout()  {
    dialog({ title: T('sign_out'), text: T('sign_out_confirm') || '确定退出登录吗？', input: false, danger: true, okText: T('sign_out') }).then(function (ok)  {
      if (!ok) return;
      api('logout', {}).then(function ()  { location.href = location.pathname; }).catch(function ()  { location.reload(); });
    });
  }

  function newFolder()  {
    dialog({ title: T('new_folder'), text: T('folder_name'), value: T('new_folder'), placeholder: T('folder_name') }).then(function (val)  {
      if (!val || !String(val).trim()) return;
      api('mkdir', { path: S.path, name: String(val).trim() }).then(function (res)  {
        toast(T('new_folder') + ' · ' + res.name);
        refresh();
      }).catch(function (e)  { toast(e.message, true); });
    });
  }
  function newFile()  {
    dialog({ title: T('new_file'), text: T('file_name'), value: 'untitled.txt', placeholder: 'untitled.txt' }).then(function (val)  {
      if (!val || !String(val).trim()) return;
      api('newfile', { path: S.path, name: String(val).trim() }).then(function (res)  {
        toast(T('new_file') + ' · ' + res.item.name);
        refresh();
        setTimeout(function ()  { openEditor(res.item); }, 220);
      }).catch(function (e)  { toast(e.message, true); });
    });
  }

  function handleBatch(act)  {
    var paths = selectedPaths();
    var items = selectedItems();
    if (!paths.length) return;
    if (act === 'copy') { setClipboard('copy', paths); }
    else if (act === 'cut') { setClipboard('cut', paths); }
    else if (act === 'compress') {
      var name = paths.length === 1 ? baseName(paths[0]) : (baseName(S.path) || 'archive');
      if (paths.length === 1 && !items[0].dir) name = name.replace(/\.[^.]+$/, '');
      openCompressSheet(paths, name);
    } else if (act === 'link') {
      if (items.length === 1) copyLink(items[0]);
    } else if (act === 'delete') {
      doDelete(paths, items.map(function (i)  { return i.name; }));
    } else if (act === 'more') {
      openBatchMore(paths, items);
    }
  }

  function openBatchMore(paths,  items)  {
    var body = openSheet(T('selected') + ' ' + paths.length + ' ' + T('items'), '');
    var acts = [
      { act: 'all', icon: 'selectall', label: T('select_all'), color: 'blue' },
      { act: 'invert', icon: 'invert', label: T('invert'), color: 'teal' },
      { act: 'none', icon: 'close', label: T('none'), color: 'gray' },
      { act: 'move', icon: 'folder', label: T('move'), color: 'violet' },
      { act: 'chmod', icon: 'lock', label: T('chmod'), color: 'slate' },
      { act: 'download', icon: 'download', label: T('download'), color: 'indigo' },
      { act: 'info', icon: 'info', label: T('info'), color: 'amber' }
    ];
    body.innerHTML = tileMenu(acts);
    bindSheetActions(body, function (act)  {
      if (act === 'all') { selectAll(); closeSheet(); return; }
      if (act === 'invert') { invertSelect(); closeSheet(); return; }
      if (act === 'none') { closeSheet(); exitSelect(); return; }
      closeSheet();
      setTimeout(function ()  {
        if (act === 'move') openMove(paths, items);
        if (act === 'chmod') openChmod(paths, items);
        if (act === 'download' && items.length === 1) downloadItem(items[0]);
        if (act === 'info' && items.length === 1) showInfo(items[0]);
      }, 60);
    });
  }

  function setSort(key)  {
    if (S.sort === key) S.dir = -S.dir;
    else { S.sort = key; S.dir = 1; }
    $('sortLabel').textContent = T('sort_' + key);
    render();
    closeSheet();
  }
  /* 排序面板：与「更多 / 已选 / 打开方式」一致的图标磁贴 */
  var SORT_FIELDS = [
    { key: 'name', icon: 'sort', color: 'blue' },
    { key: 'size', icon: 'drive', color: 'violet' },
    { key: 'time', icon: 'clock', color: 'teal' },
    { key: 'type', icon: 'file', color: 'amber' }
  ];
  function sortSheetHTML()  {
    var dirText = S.dir > 0 ? T('asc') : T('desc');
    var html = '<div class="creategrid tilegrid sortgrid">';
    SORT_FIELDS.forEach(function (f)  {
      var on = S.sort === f.key;
      html += '<button type="button" class="createitem' + (on ? ' is-on' : '') + '" data-act="sort:' + f.key + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
        + '<span class="cico cico-' + f.color + '">' + icon(f.icon, 'ic')
        + (on ? '<i class="cicheck">' + icon('check', 'ic') + '</i>' : '') + '</span>'
        + '<span class="cwrap"><span class="cname">' + esc(T('sort_' + f.key)) + '</span>'
        + (on ? '<span class="csub">' + esc(dirText) + '</span>' : '') + '</span></button>';
    });
    html += '<button type="button" class="createitem" data-act="dir">'
      + '<span class="cico cico-indigo">' + icon('sortdir', 'ic') + '</span>'
      + '<span class="cwrap"><span class="cname">' + esc(T('toggle_dir')) + '</span>'
      + '<span class="csub">' + esc(dirText) + '</span></span></button>';
    html += '</div><div class="sheet-foot"><button type="button" class="btn btn-ghost" data-sheetclose="1">'
      + esc(T('close')) + '</button></div>';
    return html;
  }
  function openSortSheet()  {
    var body = openSheet(T('sort'), T('sort_' + S.sort) + ' · ' + (S.dir > 0 ? T('asc') : T('desc')));
    body.innerHTML = sortSheetHTML();
    body.onclick = function (e)  {
      var t = e.target;
      if (!t || !t.closest) return;
      if (t.closest('[data-sheetclose]')) { closeSheet(); return; }
      var b = t.closest('[data-act]');
      if (!b) return;
      var act = b.getAttribute('data-act');
      if (act.indexOf('sort:') === 0) { setSort(act.slice(5)); return; }
      if (act === 'dir') {
        S.dir = -S.dir;
        render();
        $('sheetHint').textContent = T('sort_' + S.sort) + ' · ' + (S.dir > 0 ? T('asc') : T('desc'));
        body.innerHTML = sortSheetHTML();
      }
    };
  }
  function setViewMode(mode)  {
    S.viewMode = mode;
    try { localStorage.setItem('xiazzi.view', mode); } catch (e) {}
    $('btnViewList').classList.toggle('on', mode === 'list');
    $('btnViewGrid').classList.toggle('on', mode === 'grid');
    render();
  }

  /* ============================================================
     9.5 首次使用引导（尚未设置密码时拦截）
     ============================================================ */
  var SGV = { step: 1, busy: false, user: '' };
  var SG_WEAK = ['admin123', 'admin888', '12345678', '123456789', '11111111', 'password', 'password1', 'qwerty123', 'abc123456', 'adminadmin'];

  function openSetupGuide()  {
    var box = $('setupGuide');
    if (!box) return;
    box.hidden = false;
    box.classList.add('on');
    document.body.classList.add('sgm-open');
    $('sgmTitle').textContent = T('setup_app_title');
    $('sgmSub').textContent = T('setup_app_sub');
    sgRender(1);
  }
  function closeSetupGuide()  {
    var box = $('setupGuide');
    if (!box) return;
    box.classList.remove('on');
    box.hidden = true;
    document.body.classList.remove('sgm-open');
  }
  function sgScore(p)  {
    var s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[A-Za-z]/.test(p) && /[0-9]/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 4);
  }
  function sgPaint()  {
    var pEl = $('sgmPass'), uEl = $('sgmUser'), m = $('sgmMeter'), lv = $('sgmLv');
    if (!pEl || !m) return;
    var p = pEl.value || '';
    var u = (uEl && uEl.value || '').trim();
    var sc = p ? sgScore(p) : 0;
    var names = ['', T('setup_lv1'), T('setup_lv2'), T('setup_lv3'), T('setup_lv4')];
    m.className = 'sgm-meter' + (sc ? ' m' + sc : '');
    lv.textContent = sc ? names[sc] : '';
    var ok = {
      len: p.length >= 8,
      mix: /[A-Za-z]/.test(p) && /[0-9]/.test(p),
      same: p !== '' && u !== '' && p.toLowerCase() !== u.toLowerCase(),
      weak: p !== '' && SG_WEAK.indexOf(p.toLowerCase()) < 0
    };
    all('#sgmRules li').forEach(function (li)  {
      li.classList.toggle('ok', !!ok[li.getAttribute('data-rule')]);
    });
  }
  function sgErr(msg)  {
    var n = $('sgmErr');
    if (n) n.textContent = msg || '';
  }
  function sgRender(step)  {
    SGV.step = step;
    SGV.busy = false;
    var body = $('sgmBody');
    if (!body) return;
    if (step === 1)  {
      body.innerHTML =
        '<h3 class="sgm-h">' + esc(T('setup_hello')) + '</h3>'
        + '<p class="sgm-lead">' + esc(T('setup_lead')) + '</p>'
        + '<ul class="sgm-list">'
        + '<li class="sgm-li">' + icon('shield', 'ic') + '<span>' + esc(T('setup_p1')) + '</span></li>'
        + '<li class="sgm-li">' + icon('user', 'ic') + '<span>' + esc(T('setup_p2')) + '</span></li>'
        + '<li class="sgm-li">' + icon('lock', 'ic') + '<span>' + esc(T('setup_p3')) + '</span></li>'
        + '</ul>'
        + '<div class="sgm-acts"><button type="button" class="btn btn-primary" id="sgmStart">' + esc(T('setup_start')) + '</button></div>'
        + '<p class="sgm-note">' + esc(T('setup_note')) + '</p>';
      on($('sgmStart'), 'click', function ()  { sgRender(2); setTimeout(function ()  { var f = $('sgmPass'); if (f) { try { f.focus(); } catch (e) {} } }, 120); });
    } else if (step === 2)  {
      body.innerHTML =
        '<h3 class="sgm-h">' + esc(T('setup_title')) + '</h3>'
        + '<p class="sgm-lead">' + esc(T('setup_sub')) + '</p>'
        + '<div class="sgm-field"><label for="sgmUser">' + esc(T('setup_user_label')) + '</label>'
        + '<div class="sgm-inp"><input id="sgmUser" type="text" value="' + esc(BOOT.user || 'admin') + '" placeholder="' + esc(T('setup_user_ph')) + '" autocomplete="username" spellcheck="false"></div></div>'
        + '<div class="sgm-field"><label for="sgmPass">' + esc(T('setup_new_label')) + '</label>'
        + '<div class="sgm-inp"><input id="sgmPass" type="password" placeholder="' + esc(T('setup_new_ph')) + '" autocomplete="new-password">'
        + '<button type="button" class="sgm-eye" data-eye="sgmPass" aria-label="' + esc(T('setup_show_pass')) + '">' + icon('eye', 'ic') + '</button></div>'
        + '<div class="sgm-meter" id="sgmMeter"><i></i><i></i><i></i><i></i><span id="sgmLv"></span></div></div>'
        + '<div class="sgm-field"><label for="sgmPass2">' + esc(T('setup_new2_label')) + '</label>'
        + '<div class="sgm-inp"><input id="sgmPass2" type="password" placeholder="' + esc(T('setup_new2_ph')) + '" autocomplete="new-password">'
        + '<button type="button" class="sgm-eye" data-eye="sgmPass2" aria-label="' + esc(T('setup_show_pass')) + '">' + icon('eye', 'ic') + '</button></div></div>'
        + '<ul class="sgm-rules" id="sgmRules">'
        + '<li data-rule="len">' + esc(T('setup_rule_len')) + '</li>'
        + '<li data-rule="mix">' + esc(T('setup_rule_mix')) + '</li>'
        + '<li data-rule="same">' + esc(T('setup_rule_same')) + '</li>'
        + '<li data-rule="weak">' + esc(T('setup_rule_weak')) + '</li>'
        + '</ul>'
        + '<p class="sgm-err" id="sgmErr" role="alert" aria-live="polite"></p>'
        + '<div class="sgm-acts"><button type="button" class="btn btn-ghost" id="sgmBack">' + esc(T('setup_prev')) + '</button>'
        + '<button type="button" class="btn btn-primary" id="sgmGo">' + esc(T('setup_create')) + '</button></div>'
        + '<p class="sgm-note">' + esc(T('setup_note')) + '</p>';

      all('.sgm-eye', body).forEach(function (b)  {
        on(b, 'click', function ()  {
          var input = $(b.getAttribute('data-eye'));
          if (!input) return;
          input.type = input.type === 'password' ? 'text' : 'password';
        });
      });
      on($('sgmUser'), 'input', sgPaint);
      on($('sgmPass'), 'input', sgPaint);
      on($('sgmPass2'), 'input', sgPaint);
      on($('sgmBack'), 'click', function ()  { sgRender(1); });
      on($('sgmGo'), 'click', sgSubmit);
      all('#sgmUser,#sgmPass,#sgmPass2', body).forEach(function (inp)  {
        on(inp, 'keydown', function (ev)  { if (ev.key === 'Enter' || ev.keyCode === 13) { ev.preventDefault(); sgSubmit(); } });
      });
      sgPaint();
    } else  {
      body.innerHTML =
        '<div class="sgm-ok"><div class="sgm-tick">' + icon('check', 'ic') + '</div>'
        + '<h3 class="sgm-h">' + esc(T('setup_ok')) + '</h3>'
        + '<p class="sgm-lead">' + esc(T('setup_ok_sub')) + '</p>'
        + '<div class="sgm-acc"><span>' + esc(T('setup_ok_user')) + '</span><b>' + esc(SGV.user) + '</b></div>'
        + '<p class="sgm-note">' + esc(T('setup_ok_note')) + '</p>'
        + '<button type="button" class="btn btn-primary" style="width:100%;height:46px" id="sgmEnter">' + esc(T('setup_enter')) + '</button></div>';
      on($('sgmEnter'), 'click', function ()  { location.reload(); });
      setTimeout(function ()  { location.reload(); }, 1200);
    }
  }
  function sgSubmit()  {
    if (SGV.busy) return;
    sgErr('');
    var u = ($('sgmUser').value || '').trim();
    var p1 = $('sgmPass').value || '';
    var p2 = $('sgmPass2').value || '';
    if (!u)  { sgErr(T('setup_err_user')); return; }
    if (p1.length < 8 || !/[A-Za-z]/.test(p1) || !/[0-9]/.test(p1))  { sgErr(T('setup_err_pass')); return; }
    if (SG_WEAK.indexOf(p1.toLowerCase()) >= 0)  { sgErr(T('setup_err_weak')); return; }
    if (p1.toLowerCase() === u.toLowerCase())  { sgErr(T('setup_err_same')); return; }
    if (p1 !== p2)  { sgErr(T('setup_err_pass2')); return; }

    SGV.busy = true;
    SGV.user = u;
    var btn = $('sgmGo');
    if (btn)  { btn.disabled = true; btn.textContent = T('setup_saving'); }
    api('setup', { user: u, pass: p1, pass2: p2, remember: '1' }).then(function ()  {
      sgRender(3);
    }).catch(function (e)  {
      SGV.busy = false;
      if (btn)  { btn.disabled = false; btn.textContent = T('setup_create'); }
      sgErr(e.message);
    });
  }
  on(document, 'click', function (e)  {
    var b = e.target.closest ? e.target.closest('#sgmExit') : null;
    if (!b) return;
    dialog({ title: T('setup_exit'), text: T('sign_out_confirm') || '确定退出登录吗？', input: false, danger: true, okText: T('setup_exit') })
      .then(function (ok)  {
        if (!ok) return;
        api('logout', {}).then(function ()  { location.href = location.pathname; }).catch(function ()  { location.reload(); });
      });
  });

  /* ============================================================
     10. 初始化
     ============================================================ */
  function init()  {
    applyTheme();
    applyI18n();
    renderChips();
    $('btnViewList').classList.toggle('on', S.viewMode === 'list');
    $('btnViewGrid').classList.toggle('on', S.viewMode === 'grid');
    if (BOOT.storage) updateStorage(BOOT.storage);
    bindAll();
    var initial = '';
    try {
      var params = new URLSearchParams(location.search);
      initial = params.get('p') || '';
    } catch (e) {}
    load(initial, { view: 'files' });
    if (BOOT.setup || (S.settings && S.settings.setup_required)) {
      setTimeout(openSetupGuide, 80);
    }
  }

  /* 多选统计：独立委托，避免被其他 action 分支拦截 */
  on(document, 'click', function (e)  {
    var btn = e.target.closest ? e.target.closest('[data-sel="stat"]') : null;
    if (!btn || !$('selActions') || !$('selActions').contains(btn)) return;
    e.preventDefault();
    e.stopPropagation();
    var list = selectedItems();
    if (!list.length) { toast('请先选择文件', true); return; }
    var dirs = 0, files = 0, bytes = 0, exts = {};
    list.forEach(function (it)  {
      if (it.dir) { dirs++; return; }
      files++; bytes += Number(it.size) || 0;
      var ext = (it.ext || 'other').toLowerCase();
      exts[ext] = (exts[ext] || 0) + 1;
    });
    var keys = Object.keys(exts).sort(function (a,  b)  { return exts[b] - exts[a]; });
    var top = keys.slice(0, 7);
    var restCount = 0;
    keys.slice(7).forEach(function (k)  { restCount += exts[k]; });

    var html = '<div class="statgrid">'
      + '<div class="statcell"><b>' + list.length + '</b><span>已选项目</span></div>'
      + '<div class="statcell"><b>' + files + '</b><span>文件</span></div>'
      + '<div class="statcell"><b>' + dirs + '</b><span>文件夹</span></div>'
      + '<div class="statcell"><b>' + esc(fmtSize(bytes)) + '</b><span>总大小</span></div>'
      + '</div>';

    if (files > 0) {
      html += '<div class="statsec"><div class="statsec-h"><b>按类型</b><span>' + keys.length + ' 类</span></div>';
      top.forEach(function (x)  {
        var c = exts[x];
        var pct = Math.max(4, Math.round(c / files * 100));
        var label = x === 'other' ? '其他' : String(x).toUpperCase();
        html += '<div class="typerow">'
          + '<span class="trico">' + esc(label.slice(0, 1)) + '</span>'
          + '<span class="trname">' + esc(label) + '</span>'
          + '<span class="trbar"><i style="width:' + pct + '%"></i></span>'
          + '<span class="trnum">' + c + ' 个</span>'
          + '</div>';
      });
      if (restCount > 0) {
        html += '<div class="typerow"><span class="trico">+</span><span class="trname">其他类型</span>'
          + '<span class="trbar"><i style="width:' + Math.max(4, Math.round(restCount / files * 100)) + '%"></i></span>'
          + '<span class="trnum">' + restCount + ' 个</span></div>';
      }
      html += '</div>';
    } else {
      html += '<div class="statempty">所选项目均为文件夹，暂无文件类型分布</div>';
    }
    var sheetBody = openSheet('统计', '已选 ' + list.length + ' 项');
    sheetBody.innerHTML = html;
    sheetBody.insertAdjacentHTML('beforeend', '<div class="sheet-foot"><button type="button" class="btn btn-ghost" data-sheetclose="1">'
      + esc(T('close')) + '</button></div>');
    bindSheetActions(sheetBody, function ()  { closeSheet(); });
  });

  init();
})();
</script>

<script>
/*EUUP_UPLOAD_PROGRESS_V1-START*/
(function () {
  if (window.__EUUP_UP_UI__) { return; }
  window.__EUUP_UP_UI__ = 1;

  var CSS = `
.euup-root{position:fixed;z-index:2147483000;right:18px;bottom:18px;width:min(372px,calc(100vw - 24px));font:14px/1.45 -apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;color:#eef0f6;opacity:0;transform:translateY(14px) scale(.985);transition:opacity .22s ease,transform .26s cubic-bezier(.22,1,.36,1);pointer-events:none;text-align:left;-webkit-tap-highlight-color:transparent;}
.euup-root.euup-show{opacity:1;transform:none;pointer-events:auto;}
.euup-card{position:relative;background:linear-gradient(180deg,rgba(33,35,48,.97),rgba(19,20,29,.98));border:1px solid rgba(255,255,255,.09);border-radius:16px;box-shadow:0 22px 48px -16px rgba(0,0,0,.72),0 2px 8px rgba(0,0,0,.3);overflow:hidden;-webkit-backdrop-filter:blur(16px) saturate(1.4);backdrop-filter:blur(16px) saturate(1.4);}
.euup-head{display:flex;align-items:center;gap:8px;padding:11px 14px 9px;}
.euup-dot{width:8px;height:8px;border-radius:50%;background:#7c6cff;box-shadow:0 0 0 3px rgba(124,108,255,.18);flex:none;transition:background .2s,box-shadow .2s;}
.euup-root[data-s="done"] .euup-dot{background:#2fd39a;box-shadow:0 0 0 3px rgba(47,211,154,.18);}
.euup-root[data-s="error"] .euup-dot{background:#ff5f6d;box-shadow:0 0 0 3px rgba(255,95,109,.2);}
.euup-title{flex:1;font-size:13px;font-weight:600;letter-spacing:.2px;color:#e9ecf5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.euup-min{flex:none;width:24px;height:24px;line-height:20px;text-align:center;border:1px solid rgba(255,255,255,.13);background:rgba(255,255,255,.06);color:rgba(255,255,255,.72);border-radius:8px;font-size:15px;cursor:pointer;padding:0;font-family:inherit;transition:background .18s;}
.euup-min:hover{background:rgba(255,255,255,.14);color:#fff;}
.euup-body{padding:0 14px 13px;}
.euup-name{font-size:13.5px;font-weight:600;color:#fff;word-break:break-all;display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden;}
.euup-meta{display:flex;justify-content:space-between;gap:10px;font-size:11.5px;color:rgba(255,255,255,.55);margin-top:4px;font-variant-numeric:tabular-nums;}
.euup-speed{white-space:nowrap;color:rgba(255,255,255,.68);}
.euup-bar{position:relative;height:6px;border-radius:99px;background:rgba(255,255,255,.1);overflow:hidden;margin-top:9px;}
.euup-bar i{position:absolute;left:0;top:0;bottom:0;width:0%;border-radius:99px;background:linear-gradient(90deg,#6f5bff,#a56bff);transition:width .18s linear,background .25s;}
.euup-bar i::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,rgba(255,255,255,0),rgba(255,255,255,.42),rgba(255,255,255,0));animation:euup-shine 1.5s linear infinite;}
.euup-root[data-s="done"] .euup-bar i{background:linear-gradient(90deg,#1fc08a,#3ee0a6);}
.euup-root[data-s="done"] .euup-bar i::after{display:none;}
.euup-root[data-s="error"] .euup-bar i{background:linear-gradient(90deg,#e5484d,#ff7b81);}
.euup-root[data-s="error"] .euup-bar i::after{display:none;}
.euup-foot{display:flex;align-items:baseline;justify-content:space-between;gap:8px;margin-top:7px;}
.euup-pct{font-size:21px;font-weight:700;letter-spacing:-.6px;font-variant-numeric:tabular-nums;color:#fff;line-height:1.1;}
.euup-eta{font-size:11.5px;color:rgba(255,255,255,.6);text-align:right;}
.euup-list{margin-top:10px;border-top:1px solid rgba(255,255,255,.07);padding-top:8px;}
.euup-list:empty{display:none;}
.euup-row{display:flex;align-items:center;gap:8px;font-size:11.5px;color:rgba(255,255,255,.62);padding:2.5px 0;min-width:0;}
.euup-row b{font-weight:500;color:rgba(255,255,255,.86);flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.euup-row em{font-style:normal;font-variant-numeric:tabular-nums;flex:none;}
.euup-row.is-err em{color:#ff8a90;}
.euup-row.is-done em{color:#4fdcab;}
.euup-root.euup-mini{width:auto;max-width:66vw;}
.euup-root.euup-mini .euup-card{border-radius:99px;}
.euup-root.euup-mini .euup-head{padding:9px 14px;}
.euup-root.euup-mini .euup-body{display:none;}
.euup-root.euup-indet .euup-bar i{width:38%!important;animation:euup-indet 1.15s cubic-bezier(.65,0,.35,1) infinite;}
@keyframes euup-shine{0%{transform:translateX(-100%);}100%{transform:translateX(220%);}}
@keyframes euup-indet{0%{transform:translateX(-100%);}100%{transform:translateX(300%);}}
@media (max-width:560px){
  .euup-root{left:10px;right:10px;bottom:calc(10px + env(safe-area-inset-bottom));width:auto;max-width:none;}
  .euup-card{border-radius:15px;}
  .euup-pct{font-size:20px;}
}
@media (prefers-reduced-motion:reduce){
  .euup-root,.euup-bar i,.euup-bar i::after{animation:none!important;transition:none!important;}
}
`;

  var HTML = '<div class="euup-card">' +
      '<div class="euup-head">' +
        '<span class="euup-dot"></span>' +
        '<span class="euup-title">正在上传</span>' +
        '<button type="button" class="euup-min" aria-label="收起与展开">&minus;</button>' +
      '</div>' +
      '<div class="euup-body">' +
        '<div class="euup-name"></div>' +
        '<div class="euup-meta"><span class="euup-size"></span><span class="euup-speed"></span></div>' +
        '<div class="euup-bar"><i></i></div>' +
        '<div class="euup-foot"><span class="euup-pct">0%</span><span class="euup-eta"></span></div>' +
        '<div class="euup-list"></div>' +
      '</div>' +
    '</div>';

  var TASKS = [], SEQ = 0, root = null, refs = null;
  var hideTimer = null, visible = false, mini = false, lastRender = 0;

  /* -------------------- 工具函数 -------------------- */
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) { return Math.round(n) + ' B'; }
    var u = ['KB', 'MB', 'GB', 'TB'], i = -1;
    do { n = n / 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
  }

  function fmtDur(sec) {
    if (!isFinite(sec) || sec < 0) { return '--'; }
    sec = Math.ceil(sec);
    if (sec < 60) { return sec + ' 秒'; }
    if (sec < 3600) { return Math.floor(sec / 60) + ' 分 ' + (sec % 60) + ' 秒'; }
    return Math.floor(sec / 3600) + ' 小时 ' + Math.floor((sec % 3600) / 60) + ' 分';
  }

  function find(id) {
    for (var i = 0; i < TASKS.length; i++) { if (TASKS[i].id === id) { return TASKS[i]; } }
    return null;
  }

  function activeList() {
    var out = [];
    for (var i = 0; i < TASKS.length; i++) {
      if (TASKS[i].state !== 'done' && TASKS[i].state !== 'error') { out.push(TASKS[i]); }
    }
    return out;
  }

  /* -------------------- DOM -------------------- */
  function build() {
    if (root) { return true; }
    if (!document.body) { return false; }
    var st = document.createElement('style');
    st.id = 'euup-progress-style';
    st.textContent = CSS;
    (document.head || document.documentElement).appendChild(st);

    root = document.createElement('div');
    root.className = 'euup-root';
    root.setAttribute('data-s', 'uploading');
    root.innerHTML = HTML;
    document.body.appendChild(root);

    refs = {
      title: root.querySelector('.euup-title'),
      name: root.querySelector('.euup-name'),
      size: root.querySelector('.euup-size'),
      speed: root.querySelector('.euup-speed'),
      bar: root.querySelector('.euup-bar i'),
      pct: root.querySelector('.euup-pct'),
      eta: root.querySelector('.euup-eta'),
      list: root.querySelector('.euup-list'),
      min: root.querySelector('.euup-min')
    };

    refs.min.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      mini = !mini;
      root.classList.toggle('euup-mini', mini);
      refs.min.innerHTML = mini ? '&plus;' : '&minus;';
    });
    root.addEventListener('click', function (e) { e.stopPropagation(); });
    return true;
  }

  function show() {
    if (!build()) { return; }
    clearTimeout(hideTimer);
    if (!visible) {
      root.classList.add('euup-show');
      visible = true;
    }
  }

  function hideLater(ms) {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(function () {
      if (root) { root.classList.remove('euup-show'); }
      visible = false;
    }, ms || 1600);
  }

  /* -------------------- 渲染 -------------------- */
  function render() {
    if (!TASKS.length) { return; }
    if (!build()) { return; }

    var act = activeList();
    var main = act.length ? act[act.length - 1] : TASKS[TASKS.length - 1];
    var stateAttr = 'uploading';
    if (!act.length) { stateAttr = (main.state === 'error') ? 'error' : 'done'; }
    root.setAttribute('data-s', stateAttr);

    var multi = act.length > 1;
    var i, x;
    var sum = { total: 0, loaded: 0, known: true };
    var group = act.length ? act : TASKS;

    if (multi || !act.length) {
      for (i = 0; i < group.length; i++) {
        x = group[i];
        if (x.size > 0) { sum.total += x.size; sum.loaded += Math.min(x.loaded, x.size); }
        else { sum.known = false; sum.loaded += x.loaded || 0; }
      }
    } else {
      x = main;
      if (x.size > 0) { sum.total = x.size; sum.loaded = Math.min(x.loaded, x.size); }
      else { sum.known = false; sum.loaded = x.loaded || 0; }
    }

    /* 标题 */
    if (act.length > 1) { refs.title.textContent = '正在上传 ' + act.length + ' 项'; }
    else if (act.length === 1) { refs.title.textContent = '正在上传'; }
    else if (stateAttr === 'error') { refs.title.textContent = '上传失败'; }
    else { refs.title.textContent = '上传完成'; }

    /* 文件名 */
    if (multi) { refs.name.textContent = '共 ' + act.length + ' 个文件'; refs.name.title = ''; }
    else {
      refs.name.textContent = main.name;
      refs.name.title = main.name;
    }

    /* 百分比 */
    var pct = 0;
    var pendingServer = !act.length ? false : (main.state === 'server');
    if (sum.known && sum.total > 0) {
      pct = Math.min(100, Math.round(sum.loaded / sum.total * 100));
    }
    if (pendingServer) { pct = Math.max(pct, 99); }
    if (!act.length && stateAttr === 'done') { pct = 100; }
    if (!act.length && stateAttr === 'error') { pct = Math.min(100, pct); }

    if (!sum.known && act.length) {
      root.classList.add('euup-indet');
    } else {
      root.classList.remove('euup-indet');
      refs.bar.style.width = pct + '%';
    }
    refs.pct.textContent = sum.known ? (pct + '%') : '';

    /* 大小 */
    if (sum.known) {
      refs.size.textContent = fmtBytes(sum.loaded) + ' / ' + fmtBytes(sum.total);
    } else {
      refs.size.textContent = '已传 ' + fmtBytes(sum.loaded);
    }

    /* 速度 */
    var sp = 0;
    for (i = 0; i < act.length; i++) { if (act[i].speed > sp) { sp = act[i].speed; } }
    if (!act.length) { sp = main.avgSpeed || 0; }
    refs.speed.textContent = (act.length && sp > 0) ? (fmtBytes(sp) + '/s') : '';

    /* 剩余时间 / 状态文案 */
    if (!act.length) {
      if (stateAttr === 'error') {
        refs.eta.textContent = main.err || '上传失败';
      } else {
        var used = Math.max(0.4, ((main.end || Date.now()) - main.start) / 1000);
        refs.eta.textContent = '用时 ' + fmtDur(used);
      }
    } else if (pendingServer) {
      refs.eta.textContent = '等待服务器处理…';
    } else if (sum.known && sp > 0) {
      var left = (sum.total - sum.loaded) / sp;
      refs.eta.textContent = '预计剩余 ' + fmtDur(left);
    } else {
      refs.eta.textContent = '计算中…';
    }

    /* 多文件明细 */
    if (act.length > 1) {
      var html = '', start = Math.max(0, act.length - 4);
      for (i = start; i < act.length; i++) {
        x = act[i];
        var p = (x.size > 0) ? Math.min(100, Math.round(x.loaded / x.size * 100)) : 0;
        var txt = (x.state === 'server') ? '处理中' : (p + '%');
        html += '<div class="euup-row"><b>' + esc(x.name) + '</b><em>' + txt + '</em></div>';
      }
      if (act.length > 4) {
        html = '<div class="euup-row"><b>…还有 ' + (act.length - 4) + ' 个文件</b><em></em></div>' + html;
      }
      refs.list.innerHTML = html;
    } else {
      refs.list.innerHTML = '';
    }

    show();
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c];
    });
  }

  /* -------------------- 任务管理 -------------------- */
  function newTask(name, size) {
    if (!activeList().length) { TASKS = []; }
    var t = {
      id: ++SEQ,
      name: name || '上传文件',
      size: Number(size) || 0,
      loaded: 0,
      speed: 0,
      avgSpeed: 0,
      state: 'pending',
      start: Date.now(),
      lastT: Date.now(),
      lastL: 0,
      end: 0,
      err: ''
    };
    TASKS.push(t);
    render();
    return t;
  }

  function updTask(id, loaded, total) {
    var t = find(id);
    if (!t || t.state === 'done' || t.state === 'error') { return; }
    loaded = Number(loaded) || 0;
    if (total > 0) { t.size = Number(total) || t.size; }
    t.loaded = loaded;
    t.state = 'uploading';

    var now = Date.now();
    var dt = (now - t.lastT) / 1000;
    if (dt > 0.12) {
      var inst = (loaded - t.lastL) / dt;
      if (inst >= 0) {
        t.speed = t.speed ? (t.speed * 0.55 + inst * 0.45) : inst;
      }
      t.lastT = now;
      t.lastL = loaded;
    }
    render();
  }

  function serverWait(id) {
    var t = find(id);
    if (!t || t.state === 'done' || t.state === 'error') { return; }
    t.state = 'server';
    if (t.size > 0) { t.loaded = t.size; }
    render();
  }

  function endTask(id, ok, note) {
    var t = find(id);
    if (!t || t.state === 'done' || t.state === 'error') { return; }
    t.end = Date.now();
    var used = Math.max(0.2, (t.end - t.start) / 1000);
    t.avgSpeed = t.loaded > 0 ? t.loaded / used : 0;
    if (ok) {
      t.state = 'done';
      if (t.size > 0) { t.loaded = t.size; }
    } else {
      t.state = 'error';
      t.err = note || '上传失败';
    }
    render();

    if (!activeList().length) {
      var bad = false;
      for (var i = 0; i < TASKS.length; i++) { if (TASKS[i].state === 'error') { bad = true; } }
      hideLater(bad ? 3400 : 1700);
    }
  }

  /* -------------------- 拦截上传 -------------------- */
  function describeBody(body) {
    if (!body) { return null; }
    var i, v;
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      var cnt = 0, size = 0, firstName = '';
      try {
        if (typeof body.forEach === 'function') {
          body.forEach(function (val) {
            if (val && typeof val === 'object' && typeof val.size === 'number' && typeof val.name === 'string') {
              cnt++;
              size += val.size;
              if (!firstName) { firstName = val.name; }
            }
          });
        } else {
          return { name: '上传文件', size: 0 };
        }
      } catch (e) { return null; }
      if (!cnt) { return null; }
      return { name: cnt > 1 ? (firstName + ' 等 ' + cnt + ' 个文件') : firstName, size: size, count: cnt };
    }
    if (typeof File !== 'undefined' && body instanceof File) {
      return { name: body.name, size: body.size, count: 1 };
    }
    return null;
  }

  var XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype && XHR.prototype.send) {
    var origOpen = XHR.prototype.open;
    var origSend = XHR.prototype.send;

    XHR.prototype.open = function (m, u) {
      this.__euup = null;
      return origOpen.apply(this, arguments);
    };

    XHR.prototype.send = function (body) {
      var xhr = this;
      try {
        var info = describeBody(body);
        if (info) {
          var t = newTask(info.name, info.size);
          xhr.__euup = t.id;

          if (xhr.upload && xhr.upload.addEventListener) {
            xhr.upload.addEventListener('progress', function (e) {
              var total = e.lengthComputable ? e.total : (info.size || 0);
              updTask(t.id, e.loaded, total);
            });
            xhr.upload.addEventListener('load', function () {
              serverWait(t.id);
            });
            xhr.upload.addEventListener('error', function () {
              endTask(t.id, false, '上传中断');
            });
            xhr.upload.addEventListener('abort', function () {
              endTask(t.id, false, '已取消');
            });
          }
          xhr.addEventListener('loadend', function () {
            endTask(t.id, xhr.status >= 200 && xhr.status < 400, 'HTTP ' + xhr.status);
          });
          xhr.addEventListener('error', function () {
            endTask(t.id, false, '网络错误');
          });
          xhr.addEventListener('abort', function () {
            endTask(t.id, false, '已取消');
          });
        }
      } catch (e) { /* 绝不影响原上传 */ }
      return origSend.apply(xhr, arguments);
    };
  }

  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      var body = (init && init.body) || null;
      var info = describeBody(body);
      if (!info) { return origFetch.apply(this, arguments); }
      var t = newTask(info.name, info.size);
      serverWait(t.id);
      var p = origFetch.apply(this, arguments);
      if (p && p.then) {
        p.then(function (r) {
          endTask(t.id, r && r.ok, r ? ('HTTP ' + r.status) : '');
          return r;
        }, function (err) {
          endTask(t.id, false, '网络错误');
          throw err;
        });
      }
      return p;
    };
  }

  /* 页面卸载时若有未完成任务，不做处理，避免误报 */
})();
/*EUUP_UPLOAD_PROGRESS_V1-END*/
</script>
</body>
</html>
