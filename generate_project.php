<?php
// generate_project.php
// شغّل هذا الملف في المتصفح: http://localhost/generate_project.php
// سيولّد مشروع The Witcher Store كامل في ملف ZIP جاهز للتحميل

set_time_limit(0);
$root = __DIR__ . '/thewitcherstore_build';
@mkdir($root, 0755, true);

$files = [];

// =========================================================
// helper
// =========================================================
function w($path, $content) {
    global $root;
    $full = $root . '/' . ltrim($path, '/');
    @mkdir(dirname($full), 0755, true);
    file_put_contents($full, $content);
}

// =========================================================
// 1) CONFIG
// =========================================================
w('config/config.php', <<<'PHP'
<?php
return [
    'app' => [
        'name'     => getenv('APP_NAME') ?: 'The Witcher Store',
        'url'      => getenv('APP_URL') ?: 'http://localhost',
        'env'      => getenv('APP_ENV') ?: 'production',
        'debug'    => filter_var(getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOL),
        'timezone' => 'Africa/Cairo',
        'locale'   => 'ar',
    ],
    'db' => [
        'host'    => getenv('DB_HOST') ?: 'localhost',
        'name'    => getenv('DB_NAME') ?: 'witcher_store',
        'user'    => getenv('DB_USER') ?: 'root',
        'pass'    => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
    'session' => [
        'name' => 'twc_session', 'lifetime' => 7200,
        'secure' => false, 'httponly' => true, 'samesite' => 'Lax',
    ],
    'security' => [
        'max_login_attempts' => 5, 'lockout_minutes' => 15, 'password_min' => 8,
    ],
    'uploads' => [
        'path' => __DIR__ . '/../public/uploads',
        'url'  => '/uploads',
        'max_size' => 5 * 1024 * 1024,
        'mimes' => ['image/jpeg','image/png','image/webp'],
        'ext'   => ['jpg','jpeg','png','webp'],
    ],
];
PHP);

w('config/config.sample.php', "<?php\n// Copy to database.php if installing manually\nreturn [\n    'host' => 'localhost',\n    'name' => 'witcher_store',\n    'user' => 'root',\n    'pass' => '',\n    'charset' => 'utf8mb4',\n];\n");

// =========================================================
// 2) HELPERS
// =========================================================
w('app/helpers/functions.php', <<<'PHP'
<?php
declare(strict_types=1);

function config(string $key, $default = null) {
    static $config = null;
    if ($config === null) {
        $config = require __DIR__ . '/../../config/config.php';
        $dbFile = __DIR__ . '/../../config/database.php';
        if (file_exists($dbFile)) $config['db'] = require $dbFile;
    }
    $parts = explode('.', $key); $val = $config;
    foreach ($parts as $p) { if (!is_array($val) || !array_key_exists($p,$val)) return $default; $val = $val[$p]; }
    return $val;
}
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $c = config('db');
        $dsn = "mysql:host={$c['host']};dbname={$c['name']};charset={$c['charset']}";
        $pdo = new PDO($dsn, $c['user'], $c['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}
function e(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function url(string $path = ''): string { return rtrim(config('app.url'), '/') . '/' . ltrim($path, '/'); }
function asset(string $p): string { return url('assets/' . ltrim($p, '/')); }
function redirect(string $p): void { header('Location: ' . (str_starts_with($p,'http') ? $p : url($p))); exit; }
function csrf_token(): string { if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(32)); return $_SESSION['_csrf']; }
function csrf_field(): string { return '<input type="hidden" name="_csrf" value="'.csrf_token().'">'; }
function verify_csrf(): void {
    $t = $_POST['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!$t || !hash_equals($_SESSION['_csrf'] ?? '', $t)) { http_response_code(419); exit('CSRF mismatch'); }
}
function flash(string $k, ?string $m = null) {
    if ($m !== null) { $_SESSION['_flash'][$k] = $m; return; }
    $v = $_SESSION['_flash'][$k] ?? null; unset($_SESSION['_flash'][$k]); return $v;
}
function auth_user(): ?array {
    if (empty($_SESSION['user_id'])) return null;
    static $u = null;
    if ($u === null) {
        $s = db()->prepare("SELECT * FROM users WHERE id=? AND status='active' LIMIT 1");
        $s->execute([$_SESSION['user_id']]); $u = $s->fetch() ?: null;
    }
    return $u;
}
function auth_admin(): ?array {
    if (empty($_SESSION['admin_id'])) return null;
    static $a = null;
    if ($a === null) {
        $s = db()->prepare("SELECT a.*, r.slug AS role_slug, r.is_super FROM admins a JOIN roles r ON r.id=a.role_id WHERE a.id=? AND a.status='active' LIMIT 1");
        $s->execute([$_SESSION['admin_id']]); $a = $s->fetch() ?: null;
        if ($a) $a['permissions'] = admin_permissions((int)$a['role_id'], (bool)$a['is_super']);
    }
    return $a;
}
function admin_permissions(int $roleId, bool $isSuper): array {
    if ($isSuper) return ['*'];
    $s = db()->prepare("SELECT p.slug FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=?");
    $s->execute([$roleId]); return array_column($s->fetchAll(), 'slug');
}
function admin_can(string $perm): bool {
    $a = auth_admin(); if (!$a) return false;
    if (in_array('*', $a['permissions'], true)) return true;
    return in_array($perm, $a['permissions'], true);
}
function setting(string $k, $d = null) {
    static $cache = null;
    if ($cache === null) {
        try { $rows = db()->query("SELECT `key`,`value` FROM settings")->fetchAll(); $cache = array_column($rows,'value','key'); }
        catch (Throwable $e) { $cache = []; }
    }
    return $cache[$k] ?? $d;
}
function log_activity(string $action, ?string $tt = null, ?int $tid = null, ?string $desc = null): void {
    $a = auth_admin();
    $s = db()->prepare("INSERT INTO activity_logs (admin_id,action,target_type,target_id,description,ip_address,user_agent) VALUES (?,?,?,?,?,?,?)");
    $s->execute([$a['id'] ?? null, $action, $tt, $tid, $desc, $_SERVER['REMOTE_ADDR'] ?? null, substr($_SERVER['HTTP_USER_AGENT'] ?? '',0,300)]);
}
function json_response($data, int $code = 200): void {
    http_response_code($code); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE); exit;
}
function view(string $v, array $data = []): void {
    extract($data, EXTR_SKIP);
    $f = __DIR__ . '/../views/' . str_replace('.', '/', $v) . '.php';
    if (!file_exists($f)) { http_response_code(500); exit("View not found: $v"); }
    require $f;
}
function slugify(string $s): string {
    $s = preg_replace('/[^\p{L}\p{N}]+/u', '-', $s);
    return trim(mb_strtolower($s), '-') ?: 'item-' . time();
}
function lang(string $k, ?string $d = null): string { return $d ?? $k; }
PHP);

w('app/helpers/security.php', <<<'PHP'
<?php
declare(strict_types=1);
function hash_password(string $p): string { return password_hash($p, PASSWORD_BCRYPT, ['cost'=>12]); }
function verify_password(string $p, string $h): bool { return password_verify($p, $h); }
function random_token(int $b = 32): string { return bin2hex(random_bytes($b)); }
function rate_limit_check(string $email, string $ip, string $type='user'): bool {
    $max = (int)config('security.max_login_attempts'); $mins = (int)config('security.lockout_minutes');
    $s = db()->prepare("SELECT COUNT(*) FROM login_attempts WHERE (email=? OR ip_address=?) AND user_type=? AND success=0 AND created_at > (NOW() - INTERVAL ? MINUTE)");
    $s->execute([$email,$ip,$type,$mins]); return (int)$s->fetchColumn() < $max;
}
function record_login_attempt(string $email, string $ip, bool $ok, string $type='user'): void {
    db()->prepare("INSERT INTO login_attempts (email,ip_address,user_type,success) VALUES (?,?,?,?)")->execute([$email,$ip,$type,$ok?1:0]);
}
function secure_session_start(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $s = config('session');
    session_name($s['name']);
    session_set_cookie_params(['lifetime'=>$s['lifetime'],'path'=>'/','secure'=>$s['secure'],'httponly'=>$s['httponly'],'samesite'=>$s['samesite']]);
    session_start();
    if (empty($_SESSION['_started'])) { session_regenerate_id(true); $_SESSION['_started'] = time(); }
}
PHP);

w('app/helpers/upload.php', <<<'PHP'
<?php
declare(strict_types=1);
function upload_image(array $file, string $folder = 'general'): ?string {
    if (!isset($file['tmp_name']) || $file['error'] !== UPLOAD_ERR_OK) return null;
    $cfg = config('uploads');
    if ($file['size'] > $cfg['max_size']) throw new RuntimeException('File too large');
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $cfg['ext'], true)) throw new RuntimeException('Invalid extension');
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $mime = $fi->file($file['tmp_name']);
    if (!in_array($mime, $cfg['mimes'], true)) throw new RuntimeException('Invalid mime');
    $dir = $cfg['path'] . '/' . $folder;
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $name = bin2hex(random_bytes(16)) . '.' . $ext;
    if (!move_uploaded_file($file['tmp_name'], "$dir/$name")) throw new RuntimeException('Upload failed');
    return $folder . '/' . $name;
}
function delete_upload(?string $p): void {
    if (!$p) return; $full = config('uploads.path') . '/' . ltrim($p,'/');
    if (is_file($full)) @unlink($full);
}
PHP);

w('app/helpers/validator.php', "<?php\ndeclare(strict_types=1);\nfunction validate_email(string \$e): bool { return (bool)filter_var(\$e, FILTER_VALIDATE_EMAIL); }\n");

// =========================================================
// 3) SERVICES
// =========================================================
w('app/services/WalletService.php', <<<'PHP'
<?php
declare(strict_types=1);
class WalletService {
    public static function getOrCreate(int $userId): array {
        $s = db()->prepare("SELECT * FROM wallets WHERE user_id=?"); $s->execute([$userId]);
        $w = $s->fetch(); if ($w) return $w;
        db()->prepare("INSERT INTO wallets (user_id,balance) VALUES (?,0)")->execute([$userId]);
        $s = db()->prepare("SELECT * FROM wallets WHERE user_id=?"); $s->execute([$userId]); return $s->fetch();
    }
    public static function credit(int $uid, float $amt, string $type, ?string $ref=null, ?string $desc=null, ?int $aid=null): float {
        if ($amt <= 0) throw new InvalidArgumentException('Amount > 0');
        $pdo = db(); $pdo->beginTransaction();
        try {
            $s = $pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $s->execute([$uid]);
            $before = (float)($s->fetchColumn() ?: 0); $after = $before + $amt;
            $pdo->prepare("UPDATE wallets SET balance=?, total_deposited = total_deposited + ? WHERE user_id=?")
                ->execute([$after, $type==='deposit'?$amt:0, $uid]);
            $pdo->prepare("INSERT INTO wallet_transactions (user_id,type,amount,balance_before,balance_after,reference,description,admin_id) VALUES (?,?,?,?,?,?,?,?)")
                ->execute([$uid,$type,$amt,$before,$after,$ref,$desc,$aid]);
            $pdo->commit(); return $after;
        } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }
    public static function debit(int $uid, float $amt, string $type, ?string $ref=null, ?string $desc=null, ?int $aid=null): float {
        if ($amt <= 0) throw new InvalidArgumentException('Amount > 0');
        $pdo = db(); $pdo->beginTransaction();
        try {
            $s = $pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $s->execute([$uid]);
            $before = (float)($s->fetchColumn() ?: 0);
            if ($before < $amt) throw new RuntimeException('Insufficient balance');
            $after = $before - $amt;
            $pdo->prepare("UPDATE wallets SET balance=?, total_spent = total_spent + ? WHERE user_id=?")
                ->execute([$after, $type==='purchase'?$amt:0, $uid]);
            $pdo->prepare("INSERT INTO wallet_transactions (user_id,type,amount,balance_before,balance_after,reference,description,admin_id) VALUES (?,?,?,?,?,?,?,?)")
                ->execute([$uid,$type,-$amt,$before,$after,$ref,$desc,$aid]);
            $pdo->commit(); return $after;
        } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }
}
PHP);

w('app/services/NotificationService.php', <<<'PHP'
<?php
declare(strict_types=1);
class NotificationService {
    public static function notifyUser(int $uid, string $type, string $title, ?string $msg=null, ?string $url=null): void {
        db()->prepare("INSERT INTO notifications (user_id,is_admin,type,title,message,url) VALUES (?,0,?,?,?,?)")->execute([$uid,$type,$title,$msg,$url]);
    }
    public static function notifyAdmins(string $type, string $title, ?string $msg=null, ?string $url=null): void {
        db()->prepare("INSERT INTO notifications (user_id,is_admin,type,title,message,url) VALUES (NULL,1,?,?,?,?)")->execute([$type,$title,$msg,$url]);
    }
}
PHP);

w('app/services/CouponService.php', <<<'PHP'
<?php
declare(strict_types=1);
class CouponService {
    public static function validate(string $code, float $sub, int $gid, int $pid, int $uid, bool $lock=false): array {
        $sql = "SELECT * FROM coupons WHERE code=? AND status=1 LIMIT 1" . ($lock ? " FOR UPDATE" : "");
        $s = db()->prepare($sql); $s->execute([$code]); $c = $s->fetch();
        if (!$c) throw new RuntimeException('كود الخصم غير صحيح');
        $now = time();
        if ($c['starts_at'] && strtotime($c['starts_at']) > $now) throw new RuntimeException('الكوبون غير مفعل');
        if ($c['ends_at'] && strtotime($c['ends_at']) < $now) throw new RuntimeException('انتهى الكوبون');
        if ($c['usage_limit'] !== null && $c['used_count'] >= $c['usage_limit']) throw new RuntimeException('تم استهلاك الكوبون');
        if ($sub < (float)$c['min_order']) throw new RuntimeException('الحد الأدنى غير محقق');
        if ($c['apply_to']==='game' && (int)$c['game_id']!==$gid) throw new RuntimeException('غير صالح لهذه اللعبة');
        if ($c['apply_to']==='product' && (int)$c['product_id']!==$pid) throw new RuntimeException('غير صالح لهذا المنتج');
        $s = db()->prepare("SELECT COUNT(*) FROM coupon_usages WHERE coupon_id=? AND user_id=?"); $s->execute([$c['id'],$uid]);
        if ((int)$s->fetchColumn() >= (int)$c['user_usage_limit']) throw new RuntimeException('استخدمت الكوبون سابقًا');
        $d = $c['type']==='percentage' ? $sub * ((float)$c['value']/100) : (float)$c['value'];
        if ($c['max_discount'] !== null) $d = min($d, (float)$c['max_discount']);
        $d = min($d, $sub);
        return ['id'=>(int)$c['id'], 'discount'=>round($d,2), 'coupon'=>$c];
    }
}
PHP);

w('app/services/OrderService.php', <<<'PHP'
<?php
declare(strict_types=1);
class OrderService {
    public static function nextOrderNumber(): string {
        $prefix = setting('order_prefix','TWC'); $date = date('Ymd');
        for ($i=0; $i<10; $i++) {
            $s = db()->prepare("SELECT COUNT(*) FROM orders WHERE DATE(created_at)=CURDATE()"); $s->execute();
            $seq = (int)$s->fetchColumn() + 1 + $i;
            $n = sprintf('%s-%s-%06d', $prefix, $date, $seq);
            $c = db()->prepare("SELECT 1 FROM orders WHERE order_number=?"); $c->execute([$n]);
            if (!$c->fetchColumn()) return $n;
        }
        return $prefix.'-'.$date.'-'.bin2hex(random_bytes(3));
    }
    public static function createWalletOrder(array $data): array {
        $pdo = db(); $pdo->beginTransaction();
        try {
            $s = $pdo->prepare("SELECT * FROM products WHERE id=? AND status=1 FOR UPDATE");
            $s->execute([$data['product_id']]); $p = $s->fetch();
            if (!$p) throw new RuntimeException('المنتج غير متاح');
            $qty = max(1,(int)($data['quantity'] ?? 1));
            $price = (float)$p['price']; $sub = $price * $qty;
            $disc = 0.0; $cid = null;
            if (!empty($data['coupon_code'])) {
                $c = CouponService::validate($data['coupon_code'], $sub, (int)$p['game_id'], (int)$p['id'], (int)$data['user_id'], true);
                $disc = $c['discount']; $cid = $c['id'];
            }
            $final = max(0, $sub - $disc);
            $on = self::nextOrderNumber();
            $s = $pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $s->execute([$data['user_id']]);
            $bb = (float)($s->fetchColumn() ?: 0);
            if ($bb < $final) throw new RuntimeException('رصيد غير كافٍ');
            $ba = $bb - $final;
            $pdo->prepare("UPDATE wallets SET balance=?, total_spent=total_spent+? WHERE user_id=?")->execute([$ba,$final,$data['user_id']]);
            $pdo->prepare("INSERT INTO orders (order_number,user_id,game_id,product_id,quantity,price,discount,coupon_id,final_price,payment_method,customer_data,status) VALUES (?,?,?,?,?,?,?,?,?,'wallet',?,'pending')")
                ->execute([$on,$data['user_id'],$p['game_id'],$p['id'],$qty,$price,$disc,$cid,$final,json_encode($data['customer_data'] ?? [], JSON_UNESCAPED_UNICODE)]);
            $oid = (int)$pdo->lastInsertId();
            $pdo->prepare("INSERT INTO wallet_transactions (user_id,type,amount,balance_before,balance_after,reference,description) VALUES (?,'purchase',?,?,?,?,?)")
                ->execute([$data['user_id'],-$final,$bb,$ba,$on,"Order $on"]);
            if ($cid) {
                $pdo->prepare("INSERT INTO coupon_usages (coupon_id,user_id,order_id,discount_amount) VALUES (?,?,?,?)")->execute([$cid,$data['user_id'],$oid,$disc]);
                $pdo->prepare("UPDATE coupons SET used_count=used_count+1 WHERE id=?")->execute([$cid]);
            }
            $pdo->prepare("INSERT INTO order_status_history (order_id,status,note) VALUES (?,'pending','Order created')")->execute([$oid]);
            $pdo->commit();
            NotificationService::notifyUser((int)$data['user_id'],'order_created','تم إنشاء الطلب',"رقم الطلب: $on","/orders/$oid");
            return ['id'=>$oid,'order_number'=>$on,'final_price'=>$final];
        } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }
    public static function refund(int $oid, int $aid, ?string $note=null): void {
        $pdo = db(); $pdo->beginTransaction();
        try {
            $s = $pdo->prepare("SELECT * FROM orders WHERE id=? FOR UPDATE"); $s->execute([$oid]);
            $o = $s->fetch();
            if (!$o) throw new RuntimeException('الطلب غير موجود');
            if ($o['status']==='refunded') throw new RuntimeException('تم الاسترجاع سابقًا');
            if (!in_array($o['status'], ['pending','processing','completed'], true)) throw new RuntimeException('لا يمكن الاسترجاع');
            $amt = (float)$o['final_price'];
            $s = $pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $s->execute([$o['user_id']]);
            $bb = (float)$s->fetchColumn(); $ba = $bb + $amt;
            $pdo->prepare("UPDATE wallets SET balance=? WHERE user_id=?")->execute([$ba,$o['user_id']]);
            $pdo->prepare("INSERT INTO wallet_transactions (user_id,type,amount,balance_before,balance_after,reference,description,admin_id) VALUES (?,'refund',?,?,?,?,?,?)")
                ->execute([$o['user_id'],$amt,$bb,$ba,$o['order_number'],"Refund {$o['order_number']}",$aid]);
            $pdo->prepare("UPDATE orders SET status='refunded', refunded_at=NOW() WHERE id=?")->execute([$oid]);
            $pdo->prepare("INSERT INTO order_status_history (order_id,status,note,admin_id) VALUES (?,'refunded',?,?)")->execute([$oid,$note,$aid]);
            $pdo->commit();
        } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }
}
PHP);

w('app/services/DepositService.php', <<<'PHP'
<?php
declare(strict_types=1);
class DepositService {
    public static function approve(int $id, int $aid): void {
        $pdo = db(); $pdo->beginTransaction();
        try {
            $s = $pdo->prepare("SELECT * FROM deposits WHERE id=? FOR UPDATE"); $s->execute([$id]);
            $d = $s->fetch();
            if (!$d) throw new RuntimeException('غير موجود');
            if ($d['status']!=='pending') throw new RuntimeException('تمت معالجته');
            $amt = (float)$d['amount'];
            $s = $pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $s->execute([$d['user_id']]);
            $bb = (float)($s->fetchColumn() ?: 0); $ba = $bb + $amt;
            $pdo->prepare("UPDATE wallets SET balance=?, total_deposited=total_deposited+? WHERE user_id=?")->execute([$ba,$amt,$d['user_id']]);
            $pdo->prepare("INSERT INTO wallet_transactions (user_id,type,amount,balance_before,balance_after,reference,description,admin_id) VALUES (?,'deposit',?,?,?,?,?,?)")
                ->execute([$d['user_id'],$amt,$bb,$ba,'DEP-'.$d['id'],'Deposit approved',$aid]);
            $pdo->prepare("UPDATE deposits SET status='approved', processed_by=?, processed_at=NOW() WHERE id=?")->execute([$aid,$id]);
            $pdo->commit();
            NotificationService::notifyUser((int)$d['user_id'],'deposit_approved','تم قبول الإيداع',"تمت إضافة $amt",'/wallet/transactions');
        } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
    }
    public static function reject(int $id, int $aid, string $note): void {
        $s = db()->prepare("UPDATE deposits SET status='rejected', admin_note=?, processed_by=?, processed_at=NOW() WHERE id=? AND status='pending'");
        $s->execute([$note,$aid,$id]);
        if ($s->rowCount()===0) throw new RuntimeException('تمت المعالجة');
        $s = db()->prepare("SELECT user_id FROM deposits WHERE id=?"); $s->execute([$id]);
        NotificationService::notifyUser((int)$s->fetchColumn(),'deposit_rejected','تم رفض الإيداع',$note,'/wallet/deposit');
    }
}
PHP);

// =========================================================
// 4) MODELS
// =========================================================
w('app/models/ProductField.php', <<<'PHP'
<?php
declare(strict_types=1);
class ProductField {
    public static function forProduct(int $pid): array {
        $s = db()->prepare("SELECT * FROM product_fields WHERE product_id=? ORDER BY sort_order,id");
        $s->execute([$pid]); return $s->fetchAll();
    }
}
PHP);

w('app/models/Setting.php', <<<'PHP'
<?php
declare(strict_types=1);
class Setting {
    public static function set(string $k, ?string $v): void {
        db()->prepare("INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)")->execute([$k,$v]);
    }
    public static function allGrouped(): array {
        $rows = db()->query("SELECT * FROM settings ORDER BY `group`,`key`")->fetchAll();
        $o = []; foreach ($rows as $r) $o[$r['group']][] = $r; return $o;
    }
}
PHP);

// =========================================================
// 5) CONTROLLERS
// =========================================================
w('app/controllers/HomeController.php', <<<'PHP'
<?php
declare(strict_types=1);
class HomeController {
    public function index(): void {
        $featuredGames = db()->query("SELECT * FROM games WHERE status=1 AND featured=1 ORDER BY sort_order LIMIT 8")->fetchAll();
        $popularProducts = db()->query("SELECT p.*, g.slug AS game_slug, g.name AS game_name FROM products p JOIN games g ON g.id=p.game_id WHERE p.status=1 ORDER BY p.sort_order LIMIT 8")->fetchAll();
        $latestProducts = db()->query("SELECT p.*, g.slug AS game_slug, g.name AS game_name FROM products p JOIN games g ON g.id=p.game_id WHERE p.status=1 ORDER BY p.id DESC LIMIT 8")->fetchAll();
        $offers = db()->query("SELECT * FROM offers WHERE status=1 AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>=NOW()) ORDER BY id DESC LIMIT 6")->fetchAll();
        $banners = db()->query("SELECT * FROM banners WHERE status=1 AND (starts_at IS NULL OR starts_at<=NOW()) AND (ends_at IS NULL OR ends_at>=NOW()) ORDER BY sort_order LIMIT 5")->fetchAll();
        $socials = db()->query("SELECT * FROM social_links WHERE status=1 ORDER BY sort_order")->fetchAll();
        $faqs = db()->query("SELECT * FROM faqs WHERE status=1 ORDER BY sort_order LIMIT 8")->fetchAll();
        $testimonials = db()->query("SELECT * FROM testimonials WHERE status=1 LIMIT 6")->fetchAll();
        view('home.index', compact('featuredGames','popularProducts','latestProducts','offers','banners','socials','faqs','testimonials'));
    }
    public function notifications(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $s = db()->prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100");
        $s->execute([$u['id']]); $rows = $s->fetchAll();
        db()->prepare("UPDATE notifications SET is_read=1 WHERE user_id=?")->execute([$u['id']]);
        view('notifications.index', ['items'=>$rows]);
    }
}
PHP);

w('app/controllers/AuthController.php', <<<'PHP'
<?php
declare(strict_types=1);
class AuthController {
    public function loginForm(): void { if (auth_user()) redirect('/'); view('auth.login'); }
    public function login(): void {
        $email = trim((string)($_POST['email'] ?? '')); $pass = (string)($_POST['password'] ?? '');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (!filter_var($email,FILTER_VALIDATE_EMAIL) || $pass==='') { flash('error','بيانات غير صحيحة'); redirect('/login'); }
        if (!rate_limit_check($email,$ip)) { flash('error','محاولات كثيرة'); redirect('/login'); }
        $s = db()->prepare("SELECT * FROM users WHERE email=? LIMIT 1"); $s->execute([$email]);
        $u = $s->fetch();
        if (!$u || !verify_password($pass,$u['password']) || $u['status']!=='active') {
            record_login_attempt($email,$ip,false); flash('error','بيانات خاطئة'); redirect('/login');
        }
        record_login_attempt($email,$ip,true);
        session_regenerate_id(true); $_SESSION['user_id'] = (int)$u['id'];
        db()->prepare("UPDATE users SET last_login_at=NOW(), last_login_ip=? WHERE id=?")->execute([$ip,$u['id']]);
        redirect('/');
    }
    public function registerForm(): void { if (auth_user()) redirect('/'); view('auth.register'); }
    public function register(): void {
        $name = trim((string)($_POST['name'] ?? '')); $email = trim((string)($_POST['email'] ?? ''));
        $phone = trim((string)($_POST['phone'] ?? '')); $pass = (string)($_POST['password'] ?? '');
        $conf = (string)($_POST['password_confirmation'] ?? '');
        $err = [];
        if (mb_strlen($name) < 2) $err[] = 'الاسم مطلوب';
        if (!filter_var($email,FILTER_VALIDATE_EMAIL)) $err[] = 'بريد غير صحيح';
        if (strlen($pass) < (int)config('security.password_min')) $err[] = 'كلمة المرور قصيرة';
        if ($pass !== $conf) $err[] = 'تأكيد كلمة المرور';
        if ($err) { flash('error', implode(' | ',$err)); redirect('/register'); }
        $s = db()->prepare("SELECT 1 FROM users WHERE email=?"); $s->execute([$email]);
        if ($s->fetchColumn()) { flash('error','البريد مستخدم'); redirect('/register'); }
        $pdo = db(); $pdo->beginTransaction();
        try {
            $pdo->prepare("INSERT INTO users (name,email,phone,password) VALUES (?,?,?,?)")->execute([$name,$email,$phone,hash_password($pass)]);
            $uid = (int)$pdo->lastInsertId();
            $pdo->prepare("INSERT INTO wallets (user_id,balance) VALUES (?,0)")->execute([$uid]);
            $pdo->commit();
            session_regenerate_id(true); $_SESSION['user_id'] = $uid;
            flash('success','مرحبًا بك!'); redirect('/');
        } catch (Throwable $e) { $pdo->rollBack(); flash('error','فشل التسجيل'); redirect('/register'); }
    }
    public function logout(): void { session_destroy(); redirect('/login'); }
    public function forgotForm(): void { view('auth.forgot'); }
    public function sendReset(): void {
        $email = trim((string)($_POST['email'] ?? ''));
        if (filter_var($email,FILTER_VALIDATE_EMAIL)) {
            $s = db()->prepare("SELECT id FROM users WHERE email=?"); $s->execute([$email]);
            if ($s->fetchColumn()) {
                $t = random_token(32);
                db()->prepare("INSERT INTO password_resets (email,token,expires_at) VALUES (?,?,DATE_ADD(NOW(),INTERVAL 1 HOUR))")->execute([$email,hash('sha256',$t)]);
                error_log("Reset: " . url("/reset-password?token=$t&email=".urlencode($email)));
            }
        }
        flash('success','إذا كان البريد موجودًا، تم إرسال الرابط'); redirect('/forgot-password');
    }
    public function resetForm(): void {
        $email = (string)($_GET['email'] ?? ''); $token = (string)($_GET['token'] ?? '');
        view('auth.reset', compact('email','token'));
    }
    public function reset(): void {
        $email = trim((string)($_POST['email'] ?? '')); $t = (string)($_POST['token'] ?? '');
        $pass = (string)($_POST['password'] ?? ''); $conf = (string)($_POST['password_confirmation'] ?? '');
        if (strlen($pass) < (int)config('security.password_min') || $pass !== $conf) { flash('error','كلمة المرور غير صحيحة'); redirect('/forgot-password'); }
        $s = db()->prepare("SELECT id FROM password_resets WHERE email=? AND token=? AND expires_at>NOW() LIMIT 1");
        $s->execute([$email,hash('sha256',$t)]); if (!$s->fetch()) { flash('error','رابط غير صالح'); redirect('/forgot-password'); }
        db()->prepare("UPDATE users SET password=? WHERE email=?")->execute([hash_password($pass),$email]);
        db()->prepare("DELETE FROM password_resets WHERE email=?")->execute([$email]);
        flash('success','تم التحديث'); redirect('/login');
    }
}
PHP);

w('app/controllers/GameController.php', <<<'PHP'
<?php
declare(strict_types=1);
class GameController {
    public function index(): void {
        $games = db()->query("SELECT * FROM games WHERE status=1 ORDER BY sort_order")->fetchAll();
        view('games.index', ['games'=>$games]);
    }
    public function show(string $slug): void {
        $s = db()->prepare("SELECT * FROM games WHERE slug=? AND status=1"); $s->execute([$slug]);
        $g = $s->fetch(); if (!$g) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; return; }
        $s = db()->prepare("SELECT * FROM products WHERE game_id=? AND status=1 ORDER BY sort_order"); $s->execute([$g['id']]);
        view('games.show', ['game'=>$g, 'products'=>$s->fetchAll()]);
    }
}
PHP);

w('app/controllers/ProductController.php', <<<'PHP'
<?php
declare(strict_types=1);
class ProductController {
    public function show(string $slug): void {
        $s = db()->prepare("SELECT p.*, g.name AS game_name, g.slug AS game_slug FROM products p JOIN games g ON g.id=p.game_id WHERE p.slug=? AND p.status=1");
        $s->execute([$slug]); $p = $s->fetch();
        if (!$p) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; return; }
        $fields = ProductField::forProduct((int)$p['id']);
        view('products.show', ['product'=>$p,'fields'=>$fields]);
    }
}
PHP);

w('app/controllers/CartController.php', <<<'PHP'
<?php
declare(strict_types=1);
class CartController {
    public function index(): void {
        $cart = $_SESSION['cart'] ?? []; $items = [];
        foreach ($cart as $pid => $qty) {
            $s = db()->prepare("SELECT p.*, g.name AS game_name FROM products p JOIN games g ON g.id=p.game_id WHERE p.id=?"); $s->execute([$pid]);
            if ($p = $s->fetch()) $items[] = ['product'=>$p,'quantity'=>$qty,'subtotal'=>$p['price']*$qty];
        }
        view('cart.index', ['items'=>$items]);
    }
    public function add(): void {
        if (!auth_user()) { json_response(['ok'=>false,'need_login'=>true], 401); }
        $pid = (int)($_POST['product_id'] ?? 0); $qty = max(1,(int)($_POST['quantity'] ?? 1));
        if ($pid <= 0) json_response(['ok'=>false], 400);
        $_SESSION['cart'][$pid] = ($_SESSION['cart'][$pid] ?? 0) + $qty;
        json_response(['ok'=>true, 'count'=>array_sum($_SESSION['cart'])]);
    }
    public function update(): void {
        $pid = (int)($_POST['product_id'] ?? 0); $qty = max(1,(int)($_POST['quantity'] ?? 1));
        if ($pid > 0) $_SESSION['cart'][$pid] = $qty; redirect('/cart');
    }
    public function remove(): void { unset($_SESSION['cart'][(int)($_POST['product_id'] ?? 0)]); redirect('/cart'); }
}
PHP);

w('app/controllers/CheckoutController.php', <<<'PHP'
<?php
declare(strict_types=1);
class CheckoutController {
    public function index(): void {
        $u = auth_user(); if (!$u) { flash('error','سجل الدخول'); redirect('/login'); }
        $cart = $_SESSION['cart'] ?? []; if (!$cart) { flash('error','سلة فارغة'); redirect('/games'); }
        $items = $this->hydrate($cart);
        $wallet = WalletService::getOrCreate((int)$u['id']);
        view('checkout.index', ['items'=>$items, 'wallet'=>$wallet]);
    }
    public function applyCoupon(): void {
        $u = auth_user(); if (!$u) json_response(['ok'=>false], 401);
        $code = trim((string)($_POST['code'] ?? '')); $cart = $_SESSION['cart'] ?? [];
        if (!$cart || !$code) json_response(['ok'=>false,'msg'=>'بيانات ناقصة']);
        $items = $this->hydrate($cart);
        if (count($items)!==1) json_response(['ok'=>false,'msg'=>'منتج واحد فقط']);
        try {
            $c = CouponService::validate($code, $items[0]['subtotal'], (int)$items[0]['game_id'], (int)$items[0]['product_id'], (int)$u['id']);
            $_SESSION['cart_coupon'] = ['code'=>$code, 'discount'=>$c['discount']];
            json_response(['ok'=>true, 'discount'=>$c['discount'], 'final'=>$items[0]['subtotal']-$c['discount']]);
        } catch (Throwable $e) { json_response(['ok'=>false,'msg'=>$e->getMessage()]); }
    }
    public function place(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $cart = $_SESSION['cart'] ?? []; if (!$cart) redirect('/games');
        $items = $this->hydrate($cart);
        if (count($items)!==1) { flash('error','منتج واحد لكل طلب'); redirect('/checkout'); }
        $p = $items[0]['product'];
        $fields = ProductField::forProduct((int)$p['id']);
        $data = [];
        foreach ($fields as $f) {
            $v = trim((string)($_POST['field_'.$f['field_name']] ?? ''));
            if ($f['required'] && $v==='') { flash('error', "الحقل {$f['field_label']} مطلوب"); redirect('/checkout'); }
            $data[$f['field_name']] = $v;
        }
        $coupon = $_SESSION['cart_coupon']['code'] ?? null;
        try {
            $o = OrderService::createWalletOrder([
                'user_id'=>(int)$u['id'], 'product_id'=>(int)$p['id'],
                'quantity'=>1, 'customer_data'=>$data, 'coupon_code'=>$coupon,
            ]);
            unset($_SESSION['cart'], $_SESSION['cart_coupon']);
            flash('success','تم إنشاء طلبك'); redirect('/orders/'.$o['id']);
        } catch (Throwable $e) { flash('error',$e->getMessage()); redirect('/checkout'); }
    }
    private function hydrate(array $cart): array {
        $items = [];
        foreach ($cart as $pid=>$qty) {
            $s = db()->prepare("SELECT p.*, g.name AS game_name FROM products p JOIN games g ON g.id=p.game_id WHERE p.id=? AND p.status=1");
            $s->execute([$pid]); $p = $s->fetch(); if (!$p) continue;
            $items[] = ['product'=>$p, 'product_id'=>(int)$p['id'], 'game_id'=>(int)$p['game_id'],
                        'quantity'=>(int)$qty, 'subtotal'=>(float)$p['price']*(int)$qty];
        }
        return $items;
    }
}
PHP);

w('app/controllers/OrderController.php', <<<'PHP'
<?php
declare(strict_types=1);
class OrderController {
    public function index(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $s = db()->prepare("SELECT o.*, p.name AS product_name, g.name AS game_name FROM orders o LEFT JOIN products p ON p.id=o.product_id LEFT JOIN games g ON g.id=o.game_id WHERE o.user_id=? ORDER BY o.id DESC");
        $s->execute([$u['id']]); view('orders.index', ['orders'=>$s->fetchAll()]);
    }
    public function show(string $id): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $s = db()->prepare("SELECT o.*, p.name AS product_name, g.name AS game_name FROM orders o LEFT JOIN products p ON p.id=o.product_id LEFT JOIN games g ON g.id=o.game_id WHERE o.id=? AND o.user_id=?");
        $s->execute([(int)$id, $u['id']]); $o = $s->fetch();
        if (!$o) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; return; }
        $s = db()->prepare("SELECT * FROM order_status_history WHERE order_id=? ORDER BY id"); $s->execute([(int)$id]);
        view('orders.show', ['order'=>$o, 'history'=>$s->fetchAll()]);
    }
}
PHP);

w('app/controllers/WalletController.php', <<<'PHP'
<?php
declare(strict_types=1);
class WalletController {
    public function index(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $w = WalletService::getOrCreate((int)$u['id']);
        $s = db()->prepare("SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 10"); $s->execute([$u['id']]);
        view('wallet.index', ['wallet'=>$w, 'recent'=>$s->fetchAll()]);
    }
    public function transactions(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $page = max(1,(int)($_GET['page'] ?? 1)); $per = 20; $off = ($page-1)*$per;
        $s = db()->prepare("SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT $per OFFSET $off"); $s->execute([$u['id']]);
        view('wallet.transactions', ['rows'=>$s->fetchAll(), 'page'=>$page]);
    }
}
PHP);

w('app/controllers/DepositController.php', <<<'PHP'
<?php
declare(strict_types=1);
class DepositController {
    public function create(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $m = db()->query("SELECT * FROM payment_methods WHERE status=1 ORDER BY sort_order")->fetchAll();
        view('deposits.create', ['methods'=>$m]);
    }
    public function store(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $mid = (int)($_POST['payment_method_id'] ?? 0);
        $amt = (float)($_POST['amount'] ?? 0);
        $sender = trim((string)($_POST['sender_number'] ?? ''));
        $tx = trim((string)($_POST['transaction_id'] ?? ''));
        $s = db()->prepare("SELECT * FROM payment_methods WHERE id=? AND status=1"); $s->execute([$mid]);
        $m = $s->fetch(); if (!$m) { flash('error','طريقة غير صالحة'); redirect('/wallet/deposit'); }
        if ($amt < (float)$m['min_amount'] || $amt > (float)$m['max_amount']) { flash('error','المبلغ غير مسموح'); redirect('/wallet/deposit'); }
        $ss = null;
        if (!empty($_FILES['screenshot']['name'])) {
            try { $ss = upload_image($_FILES['screenshot'], 'deposits'); }
            catch (Throwable $e) { flash('error',$e->getMessage()); redirect('/wallet/deposit'); }
        }
        db()->prepare("INSERT INTO deposits (user_id,payment_method_id,amount,sender_number,transaction_id,screenshot) VALUES (?,?,?,?,?,?)")
            ->execute([$u['id'],$mid,$amt,$sender,$tx,$ss]);
        NotificationService::notifyAdmins('new_deposit','طلب إيداع جديد',"المستخدم {$u['name']} طلب إيداع $amt",'/admin/deposits');
        flash('success','تم إرسال الطلب'); redirect('/wallet');
    }
}
PHP);

w('app/controllers/CouponController.php', <<<'PHP'
<?php
declare(strict_types=1);
class CouponController {
    public function index(): void {
        $c = db()->query("SELECT * FROM coupons WHERE status=1 AND (ends_at IS NULL OR ends_at>=NOW()) ORDER BY id DESC")->fetchAll();
        view('coupons.index', ['coupons'=>$c]);
    }
}
PHP);

w('app/controllers/SupportController.php', <<<'PHP'
<?php
declare(strict_types=1);
class SupportController {
    public function index(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $s = db()->prepare("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC"); $s->execute([$u['id']]);
        view('support.index', ['tickets'=>$s->fetchAll()]);
    }
    public function create(): void { view('support.create'); }
    public function store(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $sub = trim((string)($_POST['subject'] ?? '')); $msg = trim((string)($_POST['message'] ?? ''));
        $cat = trim((string)($_POST['category'] ?? 'general'));
        $pri = in_array($_POST['priority'] ?? 'medium', ['low','medium','high'], true) ? $_POST['priority'] : 'medium';
        if ($sub==='' || $msg==='') { flash('error','بيانات ناقصة'); redirect('/support/create'); }
        $pdo = db(); $pdo->beginTransaction();
        try {
            $pdo->prepare("INSERT INTO tickets (user_id,subject,category,priority) VALUES (?,?,?,?)")->execute([$u['id'],$sub,$cat,$pri]);
            $tid = (int)$pdo->lastInsertId();
            $pdo->prepare("INSERT INTO ticket_messages (ticket_id,sender_type,sender_id,message) VALUES (?,'user',?,?)")->execute([$tid,$u['id'],$msg]);
            $pdo->commit();
            NotificationService::notifyAdmins('new_ticket','تذكرة جديدة',$sub,"/admin/tickets/$tid");
            flash('success','تم إنشاء التذكرة'); redirect('/support/ticket/'.$tid);
        } catch (Throwable $e) { $pdo->rollBack(); flash('error','فشل'); redirect('/support/create'); }
    }
    public function show(string $id): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $s = db()->prepare("SELECT * FROM tickets WHERE id=? AND user_id=?"); $s->execute([(int)$id,$u['id']]);
        $t = $s->fetch(); if (!$t) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; return; }
        $s = db()->prepare("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id"); $s->execute([(int)$id]);
        view('support.show', ['ticket'=>$t, 'messages'=>$s->fetchAll()]);
    }
    public function reply(string $id): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $msg = trim((string)($_POST['message'] ?? '')); if ($msg==='') redirect('/support/ticket/'.$id);
        $s = db()->prepare("SELECT id FROM tickets WHERE id=? AND user_id=?"); $s->execute([(int)$id,$u['id']]);
        if (!$s->fetchColumn()) { http_response_code(403); return; }
        db()->prepare("INSERT INTO ticket_messages (ticket_id,sender_type,sender_id,message) VALUES (?,'user',?,?)")->execute([(int)$id,$u['id'],$msg]);
        db()->prepare("UPDATE tickets SET status='open' WHERE id=?")->execute([(int)$id]);
        redirect('/support/ticket/'.$id);
    }
}
PHP);

w('app/controllers/ProfileController.php', <<<'PHP'
<?php
declare(strict_types=1);
class ProfileController {
    public function index(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        view('profile.index', ['user'=>$u]);
    }
    public function update(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $name = trim((string)($_POST['name'] ?? '')); $phone = trim((string)($_POST['phone'] ?? ''));
        if (mb_strlen($name) < 2) { flash('error','اسم غير صحيح'); redirect('/profile'); }
        $avatar = $u['avatar'];
        if (!empty($_FILES['avatar']['name'])) {
            try { delete_upload($avatar); $avatar = upload_image($_FILES['avatar'], 'avatars'); }
            catch (Throwable $e) { flash('error',$e->getMessage()); redirect('/profile'); }
        }
        db()->prepare("UPDATE users SET name=?, phone=?, avatar=? WHERE id=?")->execute([$name,$phone,$avatar,$u['id']]);
        flash('success','تم التحديث'); redirect('/profile');
    }
    public function changePassword(): void {
        $u = auth_user(); if (!$u) redirect('/login');
        $cur = (string)($_POST['current_password'] ?? ''); $new = (string)($_POST['new_password'] ?? ''); $conf = (string)($_POST['new_password_confirmation'] ?? '');
        if (!verify_password($cur,$u['password'])) { flash('error','كلمة المرور الحالية'); redirect('/profile'); }
        if (strlen($new) < (int)config('security.password_min') || $new !== $conf) { flash('error','كلمة المرور الجديدة'); redirect('/profile'); }
        db()->prepare("UPDATE users SET password=? WHERE id=?")->execute([hash_password($new),$u['id']]);
        flash('success','تم التغيير'); redirect('/profile');
    }
}
PHP);

w('app/controllers/PageController.php', <<<'PHP'
<?php
declare(strict_types=1);
class PageController {
    public function show(string $slug): void {
        $s = db()->prepare("SELECT * FROM pages WHERE slug=? AND status=1"); $s->execute([$slug]);
        $p = $s->fetch(); if (!$p) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; return; }
        view('pages.show', ['page'=>$p]);
    }
    public function contact(): void { view('pages.contact'); }
}
PHP);

// =========================================================
// 6) PUBLIC / ROUTER
// =========================================================
w('public/index.php', <<<'PHP'
<?php
declare(strict_types=1);
define('BASE_PATH', dirname(__DIR__));
require BASE_PATH . '/app/helpers/functions.php';
require BASE_PATH . '/app/helpers/security.php';
require BASE_PATH . '/app/helpers/upload.php';
require BASE_PATH . '/app/helpers/validator.php';
spl_autoload_register(function ($c) {
    foreach (['controllers','models','services','middleware'] as $d) {
        $f = BASE_PATH . "/app/$d/$c.php"; if (file_exists($f)) { require $f; return; }
    }
});
if (!file_exists(BASE_PATH . '/config/database.php') && !str_starts_with($_SERVER['REQUEST_URI'], '/install')) {
    header('Location: /install'); exit;
}
date_default_timezone_set(config('app.timezone'));
if (config('app.debug')) { ini_set('display_errors','1'); error_reporting(E_ALL); }
else { ini_set('display_errors','0'); error_reporting(0); }
secure_session_start();
if (setting('maintenance_mode','0') === '1' && !auth_admin()) {
    http_response_code(503); require BASE_PATH.'/app/views/errors/maintenance.php'; exit;
}
require BASE_PATH . '/routes/web.php';
PHP);

w('public/.htaccess', <<<'HTACCESS'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^ index.php [L]
</IfModule>
Options -Indexes
HTACCESS);

w('.htaccess', <<<'HTACCESS'
RewriteEngine On
RewriteRule ^(.*)$ public/$1 [L]
HTACCESS);

w('routes/web.php', <<<'PHP'
<?php
declare(strict_types=1);
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = '/' . trim($uri, '/');
$method = $_SERVER['REQUEST_METHOD'];
if (in_array($method, ['POST','PUT','DELETE'], true)) verify_csrf();

$routes = [
    'GET' => [
        '/'                     => [HomeController::class,'index'],
        '/games'                => [GameController::class,'index'],
        '/game/([a-z0-9-]+)'    => [GameController::class,'show'],
        '/product/([a-z0-9-]+)' => [ProductController::class,'show'],
        '/cart'                 => [CartController::class,'index'],
        '/checkout'             => [CheckoutController::class,'index'],
        '/orders'               => [OrderController::class,'index'],
        '/orders/(\d+)'         => [OrderController::class,'show'],
        '/wallet'               => [WalletController::class,'index'],
        '/wallet/deposit'       => [DepositController::class,'create'],
        '/wallet/transactions'  => [WalletController::class,'transactions'],
        '/coupons'              => [CouponController::class,'index'],
        '/support'              => [SupportController::class,'index'],
        '/support/create'       => [SupportController::class,'create'],
        '/support/ticket/(\d+)' => [SupportController::class,'show'],
        '/profile'              => [ProfileController::class,'index'],
        '/login'                => [AuthController::class,'loginForm'],
        '/register'             => [AuthController::class,'registerForm'],
        '/logout'               => [AuthController::class,'logout'],
        '/forgot-password'      => [AuthController::class,'forgotForm'],
        '/reset-password'       => [AuthController::class,'resetForm'],
        '/page/([a-z0-9-]+)'    => [PageController::class,'show'],
        '/contact'              => [PageController::class,'contact'],
        '/notifications'        => [HomeController::class,'notifications'],
    ],
    'POST' => [
        '/register'                  => [AuthController::class,'register'],
        '/login'                     => [AuthController::class,'login'],
        '/forgot-password'           => [AuthController::class,'sendReset'],
        '/reset-password'            => [AuthController::class,'reset'],
        '/cart/add'                  => [CartController::class,'add'],
        '/cart/update'               => [CartController::class,'update'],
        '/cart/remove'               => [CartController::class,'remove'],
        '/checkout/place'            => [CheckoutController::class,'place'],
        '/checkout/apply-coupon'     => [CheckoutController::class,'applyCoupon'],
        '/wallet/deposit'            => [DepositController::class,'store'],
        '/support/create'            => [SupportController::class,'store'],
        '/support/reply/(\d+)'       => [SupportController::class,'reply'],
        '/profile/update'            => [ProfileController::class,'update'],
        '/profile/password'          => [ProfileController::class,'changePassword'],
    ],
];
$dispatch = function ($routes, $method, $uri) {
    foreach ($routes[$method] ?? [] as $pattern => $handler) {
        if (preg_match('#^'.$pattern.'$#', $uri, $m)) {
            array_shift($m); [$class,$action] = $handler;
            if (!class_exists($class)) { http_response_code(500); exit("Missing: $class"); }
            $ctrl = new $class(); call_user_func_array([$ctrl,$action], $m); return true;
        }
    }
    return false;
};
if (!$dispatch($routes, $method, $uri)) { http_response_code(404); require BASE_PATH.'/app/views/errors/404.php'; }
PHP);

// =========================================================
// 7) VIEWS
// =========================================================
w('app/views/layouts/customer.php', <<<'PHP'
<?php
$user = auth_user();
$siteName = setting('site_name','The Witcher Store');
$primary = setting('primary_color','#BEEE11');
$bg = setting('background_color','#0B0D0F');
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf" content="<?= csrf_token() ?>">
<title><?= e($pageTitle ?? $siteName) ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link href="<?= asset('css/app.css') ?>" rel="stylesheet">
<style>:root{--primary:<?=e($primary)?>;--bg:<?=e($bg)?>}</style>
</head>
<body>
<nav class="navbar navbar-expand-lg twc-nav">
  <div class="container">
    <a class="navbar-brand fw-bold" href="<?= url('/') ?>"><?= e($siteName) ?></a>
    <button class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#nav"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="nav">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="<?= url('/') ?>">الرئيسية</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= url('/games') ?>">الألعاب</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= url('/coupons') ?>">الكوبونات</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= url('/support') ?>">الدعم</a></li>
      </ul>
      <ul class="navbar-nav">
        <?php if ($user): ?>
          <li class="nav-item"><a class="nav-link" href="<?= url('/wallet') ?>">محفظتي</a></li>
          <li class="nav-item"><a class="nav-link" href="<?= url('/orders') ?>">طلباتي</a></li>
          <li class="nav-item"><a class="nav-link" href="<?= url('/logout') ?>">خروج</a></li>
        <?php else: ?>
          <li class="nav-item"><a class="nav-link" href="<?= url('/login') ?>">دخول</a></li>
          <li class="nav-item"><a class="btn btn-sm btn-primary ms-2" href="<?= url('/register') ?>">حساب جديد</a></li>
        <?php endif; ?>
        <li class="nav-item"><a class="nav-link" href="<?= url('/cart') ?>"><i class="bi bi-cart"></i></a></li>
      </ul>
    </div>
  </div>
</nav>
<main class="py-4">
  <div class="container">
    <?php if ($m = flash('success')): ?><div class="alert alert-success"><?= e($m) ?></div><?php endif; ?>
    <?php if ($m = flash('error')): ?><div class="alert alert-danger"><?= e($m) ?></div><?php endif; ?>
    <?= $content ?? '' ?>
  </div>
</main>
<footer class="twc-footer py-4 mt-5"><div class="container text-center">© <?= date('Y') ?> <?= e($siteName) ?></div></footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="<?= asset('js/app.js') ?>"></script>
</body>
</html>
PHP);

w('app/views/home/index.php', <<<'PHP'
<?php ob_start(); ?>
<?php if ($banners): ?>
<div id="hero" class="carousel slide mb-5" data-bs-ride="carousel">
  <div class="carousel-inner rounded-4 overflow-hidden">
    <?php foreach ($banners as $i => $b): ?>
      <div class="carousel-item <?= $i===0?'active':'' ?>">
        <img src="<?= url('uploads/'.$b['image']) ?>" class="d-block w-100" style="max-height:420px;object-fit:cover" alt="">
        <div class="carousel-caption text-start"><h2 class="fw-bold"><?= e($b['title']) ?></h2><p><?= e($b['description']) ?></p></div>
      </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>
<h3 class="mb-3">الألعاب المميزة</h3>
<div class="row g-3 mb-5">
  <?php foreach ($featuredGames as $g): ?>
    <div class="col-6 col-md-4 col-lg-3"><a class="card game-card h-100 text-decoration-none" href="<?= url('/game/'.$g['slug']) ?>">
      <img src="<?= $g['image'] ? url('uploads/'.$g['image']) : asset('images/placeholder.png') ?>" class="card-img-top" style="height:170px;object-fit:cover">
      <div class="card-body"><div class="fw-bold"><?= e($g['name']) ?></div></div></a></div>
  <?php endforeach; ?>
</div>
<h3 class="mb-3">الأكثر مبيعًا</h3>
<div class="row g-3 mb-5">
  <?php foreach ($popularProducts as $p): ?>
    <div class="col-6 col-md-4 col-lg-3"><a class="card product-card h-100 text-decoration-none" href="<?= url('/product/'.$p['slug']) ?>">
      <img src="<?= $p['image'] ? url('uploads/'.$p['image']) : asset('images/placeholder.png') ?>" class="card-img-top" style="height:150px;object-fit:cover">
      <div class="card-body"><div class="small text-muted"><?= e($p['game_name']) ?></div><div class="fw-bold"><?= e($p['name']) ?></div>
      <div class="price"><?= number_format((float)$p['price'],2) ?> <?= e(setting('currency','EGP')) ?></div></div></a></div>
  <?php endforeach; ?>
</div>
<h3 class="mb-3">الأسئلة الشائعة</h3>
<div class="accordion mb-5">
<?php foreach ($faqs as $i => $f): ?>
  <div class="accordion-item bg-dark border-secondary">
    <h2 class="accordion-header"><button class="accordion-button collapsed bg-dark text-light" data-bs-toggle="collapse" data-bs-target="#f<?=$i?>"><?= e($f['question']) ?></button></h2>
    <div id="f<?=$i?>" class="accordion-collapse collapse"><div class="accordion-body"><?= nl2br(e($f['answer'])) ?></div></div>
  </div>
<?php endforeach; ?>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/games/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2 class="mb-3">الألعاب</h2>
<div class="row g-3">
<?php foreach ($games as $g): ?>
  <div class="col-6 col-md-4 col-lg-3"><a class="card game-card h-100 text-decoration-none" href="<?= url('/game/'.$g['slug']) ?>">
    <img src="<?= $g['image'] ? url('uploads/'.$g['image']) : asset('images/placeholder.png') ?>" class="card-img-top" style="height:160px;object-fit:cover">
    <div class="card-body"><div class="fw-bold"><?= e($g['name']) ?></div></div></a></div>
<?php endforeach; ?>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/games/show.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row mb-4">
  <div class="col-md-4"><img class="img-fluid rounded-3" src="<?= $game['banner'] ? url('uploads/'.$game['banner']) : asset('images/placeholder.png') ?>" alt=""></div>
  <div class="col-md-8"><h1 class="fw-bold"><?= e($game['name']) ?></h1><p class="text-muted"><?= nl2br(e($game['description'])) ?></p></div>
</div>
<div class="row g-3">
<?php foreach ($products as $p): ?>
  <div class="col-md-4"><div class="card product-card p-3 h-100">
    <img src="<?= $p['image'] ? url('uploads/'.$p['image']) : asset('images/placeholder.png') ?>" style="height:140px;object-fit:cover" class="rounded mb-2">
    <div class="fw-bold"><?= e($p['name']) ?></div>
    <div class="price fs-5"><?= number_format((float)$p['price'],2) ?> <?= e(setting('currency','EGP')) ?></div>
    <div class="mt-auto d-flex gap-2">
      <button class="btn btn-primary flex-fill add-to-cart" data-id="<?= (int)$p['id'] ?>">أضف للسلة</button>
      <a class="btn btn-outline-light" href="<?= url('/product/'.$p['slug']) ?>">تفاصيل</a>
    </div>
  </div></div>
<?php endforeach; ?>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/products/show.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row g-4">
  <div class="col-md-5"><img class="img-fluid rounded-3" src="<?= $product['image'] ? url('uploads/'.$product['image']) : asset('images/placeholder.png') ?>" alt=""></div>
  <div class="col-md-7">
    <div class="text-muted"><?= e($product['game_name']) ?></div>
    <h1 class="fw-bold"><?= e($product['name']) ?></h1>
    <p><?= nl2br(e($product['description'])) ?></p>
    <div class="fs-3 fw-bold price"><?= number_format((float)$product['price'],2) ?> <?= e(setting('currency','EGP')) ?></div>
    <button class="btn btn-primary btn-lg mt-3 add-to-cart" data-id="<?= (int)$product['id'] ?>">أضف إلى السلة</button>
  </div>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/cart/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>سلة التسوق</h2>
<?php if (!$items): ?><div class="alert alert-warning">السلة فارغة</div><?php else: ?>
<table class="table table-dark">
<thead><tr><th>المنتج</th><th>اللعبة</th><th>الكمية</th><th>الإجمالي</th><th></th></tr></thead>
<tbody>
<?php $total = 0; foreach ($items as $it): $total += $it['subtotal']; ?>
<tr>
  <td><?= e($it['product']['name']) ?></td>
  <td><?= e($it['product']['game_name']) ?></td>
  <td><?= (int)$it['quantity'] ?></td>
  <td><?= number_format($it['subtotal'],2) ?></td>
  <td><form method="post" action="<?= url('/cart/remove') ?>"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><input type="hidden" name="product_id" value="<?= (int)$it['product']['id'] ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td>
</tr>
<?php endforeach; ?>
</tbody></table>
<div class="text-end fs-4">الإجمالي: <span class="price"><?= number_format($total,2) ?></span></div>
<a class="btn btn-primary btn-lg mt-3" href="<?= url('/checkout') ?>">إتمام الشراء</a>
<?php endif; ?>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/checkout/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>إتمام الشراء</h2>
<?php foreach ($items as $it): $p = $it['product']; $fields = ProductField::forProduct((int)$p['id']); ?>
<form method="post" action="<?= url('/checkout/place') ?>" class="card p-4 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <h4><?= e($p['name']) ?> — <?= number_format($it['subtotal'],2) ?></h4>
  <?php foreach ($fields as $f): ?>
    <div class="mb-2">
      <label class="form-label"><?= e($f['field_label']) ?><?= $f['required'] ? ' *' : '' ?></label>
      <?php if ($f['field_type']==='textarea'): ?>
        <textarea name="field_<?= e($f['field_name']) ?>" class="form-control" <?= $f['required']?'required':'' ?>></textarea>
      <?php elseif ($f['field_type']==='select'): ?>
        <select name="field_<?= e($f['field_name']) ?>" class="form-select" <?= $f['required']?'required':'' ?>>
          <?php foreach (array_filter(array_map('trim', explode(',', (string)$f['field_options']))) as $opt): ?>
            <option><?= e($opt) ?></option>
          <?php endforeach; ?>
        </select>
      <?php else: ?>
        <input type="<?= e($f['field_type']) ?>" name="field_<?= e($f['field_name']) ?>" class="form-control" <?= $f['required']?'required':'' ?>>
      <?php endif; ?>
    </div>
  <?php endforeach; ?>
  <div class="d-flex justify-content-between align-items-center mt-3">
    <div>رصيد المحفظة: <b><?= number_format((float)$wallet['balance'],2) ?></b></div>
    <button class="btn btn-primary btn-lg">تأكيد الشراء</button>
  </div>
</form>
<?php endforeach; ?>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/orders/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>طلباتي</h2>
<table class="table table-dark">
<thead><tr><th>رقم</th><th>المنتج</th><th>الإجمالي</th><th>الحالة</th><th></th></tr></thead>
<tbody>
<?php foreach ($orders as $o): ?>
<tr>
  <td><?= e($o['order_number']) ?></td>
  <td><?= e($o['product_name']) ?></td>
  <td><?= number_format((float)$o['final_price'],2) ?></td>
  <td><?= e($o['status']) ?></td>
  <td><a class="btn btn-sm btn-outline-light" href="<?= url('/orders/'.$o['id']) ?>">تفاصيل</a></td>
</tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/orders/show.php', <<<'PHP'
<?php ob_start(); ?>
<h2>طلب <?= e($order['order_number']) ?></h2>
<div class="card p-3 mb-3">
  <div>المنتج: <b><?= e($order['product_name']) ?></b></div>
  <div>السعر: <?= number_format((float)$order['final_price'],2) ?></div>
  <div>الحالة: <b><?= e($order['status']) ?></b></div>
  <div>التاريخ: <?= e($order['created_at']) ?></div>
</div>
<h4>سجل الحالة</h4>
<ul>
<?php foreach ($history as $h): ?>
  <li><?= e($h['status']) ?> — <?= e($h['created_at']) ?> <?= $h['note'] ? '('.e($h['note']).')' : '' ?></li>
<?php endforeach; ?>
</ul>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/wallet/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>محفظتي</h2>
<div class="row g-3 mb-4">
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">الرصيد</div><div class="fs-3 price"><?= number_format((float)$wallet['balance'],2) ?></div></div></div>
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">إجمالي الإيداع</div><div class="fs-3"><?= number_format((float)$wallet['total_deposited'],2) ?></div></div></div>
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">إجمالي الإنفاق</div><div class="fs-3"><?= number_format((float)$wallet['total_spent'],2) ?></div></div></div>
</div>
<a class="btn btn-primary" href="<?= url('/wallet/deposit') ?>">إيداع رصيد</a>
<a class="btn btn-outline-light" href="<?= url('/wallet/transactions') ?>">كل المعاملات</a>
<h4 class="mt-4">آخر المعاملات</h4>
<table class="table table-dark">
<thead><tr><th>النوع</th><th>المبلغ</th><th>الرصيد بعد</th><th>التاريخ</th></tr></thead>
<tbody>
<?php foreach ($recent as $t): ?>
<tr><td><?= e($t['type']) ?></td><td><?= number_format((float)$t['amount'],2) ?></td><td><?= number_format((float)$t['balance_after'],2) ?></td><td><?= e($t['created_at']) ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/wallet/transactions.php', <<<'PHP'
<?php ob_start(); ?>
<h2>كل المعاملات</h2>
<table class="table table-dark">
<thead><tr><th>النوع</th><th>المبلغ</th><th>قبل</th><th>بعد</th><th>التاريخ</th></tr></thead>
<tbody>
<?php foreach ($rows as $t): ?>
<tr><td><?= e($t['type']) ?></td><td><?= number_format((float)$t['amount'],2) ?></td><td><?= number_format((float)$t['balance_before'],2) ?></td><td><?= number_format((float)$t['balance_after'],2) ?></td><td><?= e($t['created_at']) ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/deposits/create.php', <<<'PHP'
<?php ob_start(); ?>
<h2>إيداع رصيد</h2>
<form method="post" action="<?= url('/wallet/deposit') ?>" enctype="multipart/form-data" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="mb-3"><label>طريقة الدفع</label>
    <select class="form-select" name="payment_method_id" required>
      <?php foreach ($methods as $m): ?><option value="<?= (int)$m['id'] ?>"><?= e($m['name']) ?> (<?= (float)$m['min_amount'] ?> - <?= (float)$m['max_amount'] ?>)</option><?php endforeach; ?>
    </select>
  </div>
  <div class="mb-3"><label>المبلغ</label><input class="form-control" type="number" step="0.01" name="amount" required></div>
  <div class="mb-3"><label>رقم المرسل</label><input class="form-control" name="sender_number" required></div>
  <div class="mb-3"><label>رقم العملية</label><input class="form-control" name="transaction_id" required></div>
  <div class="mb-3"><label>صورة الإيصال</label><input class="form-control" type="file" name="screenshot" accept="image/*" required></div>
  <button class="btn btn-primary">إرسال</button>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/coupons/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الكوبونات</h2>
<table class="table table-dark">
<thead><tr><th>الكود</th><th>النوع</th><th>القيمة</th><th>الحد الأدنى</th><th>ينتهي</th></tr></thead>
<tbody>
<?php foreach ($coupons as $c): ?>
<tr><td><b><?= e($c['code']) ?></b></td><td><?= e($c['type']) ?></td><td><?= e((string)$c['value']) ?></td><td><?= e((string)$c['min_order']) ?></td><td><?= e($c['ends_at'] ?? '—') ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/support/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الدعم</h2>
<a class="btn btn-primary mb-3" href="<?= url('/support/create') ?>">تذكرة جديدة</a>
<table class="table table-dark">
<thead><tr><th>#</th><th>الموضوع</th><th>الحالة</th><th>التاريخ</th></tr></thead>
<tbody>
<?php foreach ($tickets as $t): ?>
<tr><td><?= (int)$t['id'] ?></td><td><?= e($t['subject']) ?></td><td><?= e($t['status']) ?></td><td><?= e($t['created_at']) ?></td>
<td><a class="btn btn-sm btn-outline-light" href="<?= url('/support/ticket/'.$t['id']) ?>">فتح</a></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/support/create.php', <<<'PHP'
<?php ob_start(); ?>
<h2>تذكرة جديدة</h2>
<form method="post" action="<?= url('/support/create') ?>" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="mb-3"><label>الموضوع</label><input class="form-control" name="subject" required></div>
  <div class="mb-3"><label>الفئة</label><input class="form-control" name="category"></div>
  <div class="mb-3"><label>الأولوية</label>
    <select class="form-select" name="priority"><option value="low">منخفضة</option><option value="medium" selected>متوسطة</option><option value="high">عالية</option></select>
  </div>
  <div class="mb-3"><label>الرسالة</label><textarea class="form-control" name="message" rows="5" required></textarea></div>
  <button class="btn btn-primary">إرسال</button>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/support/show.php', <<<'PHP'
<?php ob_start(); ?>
<h2>تذكرة #<?= (int)$ticket['id'] ?> — <?= e($ticket['subject']) ?></h2>
<div class="mb-3">
<?php foreach ($messages as $m): ?>
  <div class="card p-3 mb-2" style="<?= $m['sender_type']==='admin' ? 'border-color:#BEEE11' : '' ?>">
    <div class="small text-muted"><?= e($m['sender_type']) ?> — <?= e($m['created_at']) ?></div>
    <div><?= nl2br(e($m['message'])) ?></div>
  </div>
<?php endforeach; ?>
</div>
<form method="post" action="<?= url('/support/reply/'.$ticket['id']) ?>" class="card p-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <textarea class="form-control mb-2" name="message" rows="3" required></textarea>
  <button class="btn btn-primary">رد</button>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/profile/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الملف الشخصي</h2>
<div class="row g-3">
  <div class="col-md-6">
    <form method="post" action="<?= url('/profile/update') ?>" enctype="multipart/form-data" class="card p-4">
      <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
      <div class="mb-3"><label>الاسم</label><input class="form-control" name="name" value="<?= e($user['name']) ?>" required></div>
      <div class="mb-3"><label>الهاتف</label><input class="form-control" name="phone" value="<?= e($user['phone']) ?>"></div>
      <div class="mb-3"><label>الصورة</label><input class="form-control" type="file" name="avatar" accept="image/*"></div>
      <button class="btn btn-primary">حفظ</button>
    </form>
  </div>
  <div class="col-md-6">
    <form method="post" action="<?= url('/profile/password') ?>" class="card p-4">
      <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
      <div class="mb-3"><label>كلمة المرور الحالية</label><input class="form-control" type="password" name="current_password" required></div>
      <div class="mb-3"><label>الجديدة</label><input class="form-control" type="password" name="new_password" required></div>
      <div class="mb-3"><label>تأكيد الجديدة</label><input class="form-control" type="password" name="new_password_confirmation" required></div>
      <button class="btn btn-primary">تغيير</button>
    </form>
  </div>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/auth/login.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row justify-content-center"><div class="col-md-5">
<form method="post" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <h3 class="mb-3">تسجيل الدخول</h3>
  <div class="mb-3"><label>البريد</label><input class="form-control" type="email" name="email" required></div>
  <div class="mb-3"><label>كلمة المرور</label><input class="form-control" type="password" name="password" required></div>
  <button class="btn btn-primary">دخول</button>
  <a href="<?= url('/forgot-password') ?>" class="mt-2 small">هل نسيت كلمة المرور؟</a>
</form></div></div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/auth/register.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row justify-content-center"><div class="col-md-6">
<form method="post" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <h3 class="mb-3">حساب جديد</h3>
  <div class="mb-3"><label>الاسم</label><input class="form-control" name="name" required></div>
  <div class="mb-3"><label>البريد</label><input class="form-control" type="email" name="email" required></div>
  <div class="mb-3"><label>الهاتف</label><input class="form-control" name="phone"></div>
  <div class="mb-3"><label>كلمة المرور</label><input class="form-control" type="password" name="password" required></div>
  <div class="mb-3"><label>تأكيد كلمة المرور</label><input class="form-control" type="password" name="password_confirmation" required></div>
  <button class="btn btn-primary">تسجيل</button>
</form></div></div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/auth/forgot.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row justify-content-center"><div class="col-md-5">
<form method="post" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <h3 class="mb-3">استعادة كلمة المرور</h3>
  <div class="mb-3"><label>البريد</label><input class="form-control" type="email" name="email" required></div>
  <button class="btn btn-primary">إرسال</button>
</form></div></div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/auth/reset.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row justify-content-center"><div class="col-md-5">
<form method="post" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <input type="hidden" name="token" value="<?= e($token) ?>">
  <input type="hidden" name="email" value="<?= e($email) ?>">
  <h3 class="mb-3">كلمة مرور جديدة</h3>
  <div class="mb-3"><label>الجديدة</label><input class="form-control" type="password" name="password" required></div>
  <div class="mb-3"><label>تأكيد</label><input class="form-control" type="password" name="password_confirmation" required></div>
  <button class="btn btn-primary">تحديث</button>
</form></div></div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/pages/show.php', <<<'PHP'
<?php ob_start(); ?>
<h1><?= e($page['title']) ?></h1>
<div><?= $page['content'] ?></div>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/pages/contact.php', <<<'PHP'
<?php ob_start(); ?>
<h2>اتصل بنا</h2>
<p>البريد: <?= e(setting('contact_email','support@example.com')) ?></p>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/notifications/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الإشعارات</h2>
<ul class="list-group">
<?php foreach ($items as $n): ?>
  <li class="list-group-item bg-dark text-light"><b><?= e($n['title']) ?></b><div><?= e($n['message']) ?></div></li>
<?php endforeach; ?>
</ul>
<?php $content = ob_get_clean(); require __DIR__.'/../layouts/customer.php'; PHP);

w('app/views/errors/404.php', <<<'PHP'
<?php http_response_code(404); ?>
<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>404</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
<style>body{background:#0B0D0F;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}a{color:#BEEE11}</style>
</head><body><div><h1 style="font-size:8rem;color:#BEEE11">404</h1><p>الصفحة غير موجودة</p><a href="/">العودة للرئيسية</a></div></body></html>
PHP);

w('app/views/errors/maintenance.php', <<<'PHP'
<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>Maintenance</title>
<style>body{background:#0B0D0F;color:#BEEE11;text-align:center;padding-top:20vh;font-family:sans-serif}</style></head>
<body><h1>🚧 الموقع تحت الصيانة</h1><p><?= e(setting('maintenance_message','نعود قريبًا')) ?></p></body></html>
PHP);

// =========================================================
// 8) ADMIN PANEL
// =========================================================
w('admin/index.php', <<<'PHP'
<?php
declare(strict_types=1);
define('BASE_PATH', dirname(__DIR__));
require BASE_PATH . '/app/helpers/functions.php';
require BASE_PATH . '/app/helpers/security.php';
require BASE_PATH . '/app/helpers/upload.php';
require BASE_PATH . '/app/helpers/validator.php';
spl_autoload_register(function ($c) {
    foreach (['controllers','models','services','middleware'] as $d) {
        $f = BASE_PATH . "/app/$d/$c.php"; if (file_exists($f)) { require $f; return; }
    }
    foreach (['controllers','models'] as $d) {
        $f = __DIR__ . "/$d/$c.php"; if (file_exists($f)) { require $f; return; }
    }
});
date_default_timezone_set(config('app.timezone'));
secure_session_start();
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = preg_replace('#^/admin#', '', $uri) ?: '/';
$method = $_SERVER['REQUEST_METHOD'];
if ($uri !== '/login' && !auth_admin()) { header('Location: /admin/login'); exit; }
if ($method === 'POST') verify_csrf();
require __DIR__ . '/routes.php';
PHP);

w('admin/.htaccess', "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^ index.php [L]\n");

w('admin/routes.php', <<<'PHP'
<?php
declare(strict_types=1);
$routes = [
    'GET' => [
        '/'             => ['DashboardController','index'],
        '/login'        => ['AdminAuthController','loginForm'],
        '/logout'       => ['AdminAuthController','logout'],
        '/users'        => ['UsersController','index'],
        '/users/(\d+)'  => ['UsersController','show'],
        '/games'        => ['GamesController','index'],
        '/games/create' => ['GamesController','create'],
        '/games/(\d+)/edit' => ['GamesController','edit'],
        '/categories'   => ['CategoriesController','index'],
        '/products'     => ['ProductsController','index'],
        '/products/create' => ['ProductsController','create'],
        '/products/(\d+)/edit' => ['ProductsController','edit'],
        '/products/(\d+)/fields' => ['ProductsController','fields'],
        '/orders'       => ['OrdersController','index'],
        '/orders/(\d+)' => ['OrdersController','show'],
        '/deposits'     => ['DepositsController','index'],
        '/wallet'       => ['WalletAdminController','index'],
        '/payment-methods' => ['PaymentMethodsController','index'],
        '/coupons'      => ['CouponsController','index'],
        '/offers'       => ['OffersController','index'],
        '/tickets'      => ['TicketsController','index'],
        '/tickets/(\d+)'=> ['TicketsController','show'],
        '/banners'      => ['BannersController','index'],
        '/pages'        => ['PagesController','index'],
        '/social'       => ['SocialController','index'],
        '/admins'       => ['AdminsController','index'],
        '/roles'        => ['RolesController','index'],
        '/logs'         => ['LogsController','index'],
        '/settings'     => ['SettingsController','index'],
    ],
    'POST' => [
        '/login'        => ['AdminAuthController','login'],
        '/users/(\d+)/wallet' => ['UsersController','adjustWallet'],
        '/users/(\d+)/status' => ['UsersController','toggleStatus'],
        '/games'        => ['GamesController','store'],
        '/games/(\d+)'  => ['GamesController','update'],
        '/games/(\d+)/delete' => ['GamesController','destroy'],
        '/categories'   => ['CategoriesController','store'],
        '/categories/(\d+)/delete' => ['CategoriesController','destroy'],
        '/products'     => ['ProductsController','store'],
        '/products/(\d+)' => ['ProductsController','update'],
        '/products/(\d+)/delete' => ['ProductsController','destroy'],
        '/products/(\d+)/fields' => ['ProductsController','saveFields'],
        '/orders/(\d+)/status' => ['OrdersController','updateStatus'],
        '/orders/(\d+)/refund' => ['OrdersController','refund'],
        '/deposits/(\d+)/approve' => ['DepositsController','approve'],
        '/deposits/(\d+)/reject'  => ['DepositsController','reject'],
        '/payment-methods' => ['PaymentMethodsController','store'],
        '/payment-methods/(\d+)/delete' => ['PaymentMethodsController','destroy'],
        '/coupons' => ['CouponsController','store'],
        '/coupons/(\d+)/delete' => ['CouponsController','destroy'],
        '/offers' => ['OffersController','store'],
        '/offers/(\d+)/delete' => ['OffersController','destroy'],
        '/tickets/(\d+)/reply' => ['TicketsController','reply'],
        '/banners' => ['BannersController','store'],
        '/banners/(\d+)/delete' => ['BannersController','destroy'],
        '/pages' => ['PagesController','store'],
        '/pages/(\d+)/delete' => ['PagesController','destroy'],
        '/social' => ['SocialController','store'],
        '/social/(\d+)/delete' => ['SocialController','destroy'],
        '/admins' => ['AdminsController','store'],
        '/admins/(\d+)/delete' => ['AdminsController','destroy'],
        '/roles/(\d+)' => ['RolesController','update'],
        '/settings' => ['SettingsController','save'],
    ],
];
$dispatch = function ($routes, $method, $uri) {
    foreach ($routes[$method] ?? [] as $pattern => $handler) {
        if (preg_match('#^'.$pattern.'$#', $uri, $m)) {
            array_shift($m); [$class,$action] = $handler;
            if (!class_exists($class)) { http_response_code(500); exit("Missing: $class"); }
            $ctrl = new $class(); call_user_func_array([$ctrl,$action], $m); return true;
        }
    }
    return false;
};
if (!$dispatch($routes, $method, $uri)) { http_response_code(404); echo 'Admin 404'; }
PHP);

w('admin/controllers/DashboardController.php', <<<'PHP'
<?php
declare(strict_types=1);
class DashboardController {
    public function index(): void {
        if (!admin_can('orders.view')) { http_response_code(403); exit; }
        $pdo = db();
        $stats = [
            'total_sales'      => (float)$pdo->query("SELECT COALESCE(SUM(final_price),0) FROM orders WHERE status IN ('completed','processing','pending')")->fetchColumn(),
            'today_sales'      => (float)$pdo->query("SELECT COALESCE(SUM(final_price),0) FROM orders WHERE DATE(created_at)=CURDATE()")->fetchColumn(),
            'monthly_sales'    => (float)$pdo->query("SELECT COALESCE(SUM(final_price),0) FROM orders WHERE MONTH(created_at)=MONTH(NOW()) AND YEAR(created_at)=YEAR(NOW())")->fetchColumn(),
            'total_orders'     => (int)$pdo->query("SELECT COUNT(*) FROM orders")->fetchColumn(),
            'pending_orders'   => (int)$pdo->query("SELECT COUNT(*) FROM orders WHERE status='pending'")->fetchColumn(),
            'completed_orders' => (int)$pdo->query("SELECT COUNT(*) FROM orders WHERE status='completed'")->fetchColumn(),
            'cancelled_orders' => (int)$pdo->query("SELECT COUNT(*) FROM orders WHERE status='cancelled'")->fetchColumn(),
            'total_users'      => (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn(),
            'active_users'     => (int)$pdo->query("SELECT COUNT(*) FROM users WHERE status='active'")->fetchColumn(),
            'total_games'      => (int)$pdo->query("SELECT COUNT(*) FROM games")->fetchColumn(),
            'total_products'   => (int)$pdo->query("SELECT COUNT(*) FROM products")->fetchColumn(),
            'pending_deposits' => (int)$pdo->query("SELECT COUNT(*) FROM deposits WHERE status='pending'")->fetchColumn(),
            'wallet_balance'   => (float)$pdo->query("SELECT COALESCE(SUM(balance),0) FROM wallets")->fetchColumn(),
        ];
        $topGames = $pdo->query("SELECT g.name, COUNT(o.id) c FROM orders o JOIN games g ON g.id=o.game_id GROUP BY g.id ORDER BY c DESC LIMIT 5")->fetchAll();
        $topProducts = $pdo->query("SELECT p.name, COUNT(o.id) c FROM orders o JOIN products p ON p.id=o.product_id GROUP BY p.id ORDER BY c DESC LIMIT 5")->fetchAll();
        view('dashboard', compact('stats','topGames','topProducts'));
    }
}
PHP);

w('admin/controllers/AdminAuthController.php', <<<'PHP'
<?php
declare(strict_types=1);
class AdminAuthController {
    public function loginForm(): void {
        if (auth_admin()) { header('Location: /admin'); exit; }
        view('auth/login');
    }
    public function login(): void {
        $email = trim((string)($_POST['email'] ?? '')); $pass = (string)($_POST['password'] ?? '');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (!rate_limit_check($email,$ip,'admin')) { $_SESSION['err']='Too many attempts'; header('Location: /admin/login'); exit; }
        $s = db()->prepare("SELECT * FROM admins WHERE email=? LIMIT 1"); $s->execute([$email]);
        $a = $s->fetch();
        if (!$a || !verify_password($pass,$a['password']) || $a['status']!=='active') {
            record_login_attempt($email,$ip,false,'admin');
            $_SESSION['err']='Invalid credentials'; header('Location: /admin/login'); exit;
        }
        record_login_attempt($email,$ip,true,'admin');
        session_regenerate_id(true); $_SESSION['admin_id'] = (int)$a['id'];
        db()->prepare("UPDATE admins SET last_login_at=NOW(), last_login_ip=? WHERE id=?")->execute([$ip,$a['id']]);
        log_activity('login','admin',(int)$a['id'],'Admin logged in');
        header('Location: /admin'); exit;
    }
    public function logout(): void {
        log_activity('logout','admin',(int)(auth_admin()['id'] ?? 0));
        $_SESSION = []; session_destroy();
        header('Location: /admin/login'); exit;
    }
}
PHP);

w('admin/controllers/ProductsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class ProductsController {
    public function index(): void {
        if (!admin_can('products.view')) { http_response_code(403); exit; }
        $s = db()->query("SELECT p.*, g.name game_name FROM products p JOIN games g ON g.id=p.game_id ORDER BY p.id DESC LIMIT 200");
        view('products/index', ['products'=>$s->fetchAll()]);
    }
    public function create(): void {
        if (!admin_can('products.create')) { http_response_code(403); exit; }
        $g = db()->query("SELECT id,name FROM games ORDER BY name")->fetchAll();
        view('products/form', ['product'=>null, 'games'=>$g, 'fields'=>[]]);
    }
    public function edit(string $id): void {
        if (!admin_can('products.edit')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT * FROM products WHERE id=?"); $s->execute([(int)$id]);
        $p = $s->fetch(); if (!$p) { http_response_code(404); exit; }
        $g = db()->query("SELECT id,name FROM games ORDER BY name")->fetchAll();
        $fields = ProductField::forProduct((int)$id);
        view('products/form', ['product'=>$p, 'games'=>$g, 'fields'=>$fields]);
    }
    public function store(): void {
        if (!admin_can('products.create')) { http_response_code(403); exit; }
        $d = $this->validate($_POST);
        $img = null;
        if (!empty($_FILES['image']['name'])) $img = upload_image($_FILES['image'], 'products');
        db()->prepare("INSERT INTO products (game_id,name,slug,description,image,price,old_price,cost_price,discount,sku,stock,status,featured,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            ->execute([$d['game_id'],$d['name'],$d['slug'],$d['description'],$img,$d['price'],$d['old_price'],$d['cost_price'],$d['discount'],$d['sku'],$d['stock'],$d['status'],$d['featured'],$d['sort_order']]);
        log_activity('product.create','product',(int)db()->lastInsertId(),$d['name']);
        header('Location: /admin/products'); exit;
    }
    public function update(string $id): void {
        if (!admin_can('products.edit')) { http_response_code(403); exit; }
        $d = $this->validate($_POST);
        $img = null;
        if (!empty($_FILES['image']['name'])) $img = upload_image($_FILES['image'], 'products');
        $sql = "UPDATE products SET game_id=?,name=?,slug=?,description=?,price=?,old_price=?,cost_price=?,discount=?,sku=?,stock=?,status=?,featured=?,sort_order=?";
        $args = [$d['game_id'],$d['name'],$d['slug'],$d['description'],$d['price'],$d['old_price'],$d['cost_price'],$d['discount'],$d['sku'],$d['stock'],$d['status'],$d['featured'],$d['sort_order']];
        if ($img) { $sql .= ",image=?"; $args[] = $img; }
        $sql .= " WHERE id=?"; $args[] = (int)$id;
        db()->prepare($sql)->execute($args);
        log_activity('product.update','product',(int)$id,$d['name']);
        header('Location: /admin/products/'.$id.'/edit'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('products.delete')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM products WHERE id=?")->execute([(int)$id]);
        log_activity('product.delete','product',(int)$id);
        header('Location: /admin/products'); exit;
    }
    public function fields(string $id): void {
        if (!admin_can('products.edit')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT * FROM products WHERE id=?"); $s->execute([(int)$id]);
        $p = $s->fetch(); if (!$p) { http_response_code(404); exit; }
        $fields = ProductField::forProduct((int)$id);
        view('products/fields', ['product'=>$p, 'fields'=>$fields]);
    }
    public function saveFields(string $id): void {
        if (!admin_can('products.edit')) { http_response_code(403); exit; }
        $names = $_POST['field_name'] ?? []; $labels = $_POST['field_label'] ?? [];
        $types = $_POST['field_type'] ?? []; $ph = $_POST['placeholder'] ?? [];
        $opts = $_POST['field_options'] ?? []; $req = $_POST['required'] ?? [];
        $pdo = db(); $pdo->beginTransaction();
        try {
            $pdo->prepare("DELETE FROM product_fields WHERE product_id=?")->execute([(int)$id]);
            $ins = $pdo->prepare("INSERT INTO product_fields (product_id,field_name,field_label,field_type,field_options,placeholder,required,sort_order) VALUES (?,?,?,?,?,?,?,?)");
            foreach ($names as $i => $n) {
                if (trim($n)==='') continue;
                $ins->execute([(int)$id, preg_replace('/[^a-z0-9_]/i','_',$n), $labels[$i] ?? $n,
                    in_array($types[$i] ?? 'text', ['text','number','email','select','textarea'], true) ? $types[$i] : 'text',
                    $opts[$i] ?? null, $ph[$i] ?? null, isset($req[$i]) ? 1 : 0, $i]);
            }
            $pdo->commit(); log_activity('product.fields','product',(int)$id);
        } catch (Throwable $e) { $pdo->rollBack(); $_SESSION['err'] = $e->getMessage(); }
        header('Location: /admin/products/'.$id.'/fields'); exit;
    }
    private function validate(array $in): array {
        return [
            'game_id'=>(int)($in['game_id'] ?? 0),
            'name'=>trim((string)($in['name'] ?? '')),
            'slug'=>trim((string)($in['slug'] ?? '')) ?: slugify((string)($in['name'] ?? '')),
            'description'=>(string)($in['description'] ?? ''),
            'price'=>(float)($in['price'] ?? 0),
            'old_price'=>($in['old_price'] ?? '')!=='' ? (float)$in['old_price'] : null,
            'cost_price'=>($in['cost_price'] ?? '')!=='' ? (float)$in['cost_price'] : null,
            'discount'=>(float)($in['discount'] ?? 0),
            'sku'=>trim((string)($in['sku'] ?? '')) ?: null,
            'stock'=>(int)($in['stock'] ?? -1),
            'status'=>isset($in['status']) ? 1 : 0,
            'featured'=>isset($in['featured']) ? 1 : 0,
            'sort_order'=>(int)($in['sort_order'] ?? 0),
        ];
    }
}
PHP);

w('admin/controllers/UsersController.php', <<<'PHP'
<?php
declare(strict_types=1);
class UsersController {
    public function index(): void {
        if (!admin_can('users.view')) { http_response_code(403); exit; }
        $q = trim((string)($_GET['q'] ?? ''));
        $sql = "SELECT u.*, w.balance FROM users u LEFT JOIN wallets w ON w.user_id=u.id"; $args = [];
        if ($q) { $sql .= " WHERE u.email LIKE ? OR u.name LIKE ?"; $args[] = "%$q%"; $args[] = "%$q%"; }
        $sql .= " ORDER BY u.id DESC LIMIT 200";
        $s = db()->prepare($sql); $s->execute($args);
        view('users/index', ['users'=>$s->fetchAll(), 'q'=>$q]);
    }
    public function show(string $id): void {
        if (!admin_can('users.view')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT * FROM users WHERE id=?"); $s->execute([(int)$id]);
        $u = $s->fetch(); if (!$u) { http_response_code(404); exit; }
        $w = WalletService::getOrCreate((int)$id);
        $s = db()->prepare("SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 50"); $s->execute([(int)$id]);
        $tx = $s->fetchAll();
        $s = db()->prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 30"); $s->execute([(int)$id]);
        view('users/show', ['user'=>$u, 'wallet'=>$w, 'tx'=>$tx, 'orders'=>$s->fetchAll()]);
    }
    public function adjustWallet(string $id): void {
        if (!admin_can('wallet.manage')) { http_response_code(403); exit; }
        $type = $_POST['type'] ?? 'credit';
        $amt = (float)($_POST['amount'] ?? 0);
        $reason = trim((string)($_POST['reason'] ?? 'Admin adjustment'));
        if ($amt <= 0) { $_SESSION['err']='Invalid amount'; header('Location: /admin/users/'.$id); exit; }
        try {
            if ($type==='debit') WalletService::debit((int)$id,$amt,'admin_debit',null,$reason,(int)auth_admin()['id']);
            else WalletService::credit((int)$id,$amt,'admin_credit',null,$reason,(int)auth_admin()['id']);
            log_activity('wallet.'.$type,'user',(int)$id,"$amt — $reason");
        } catch (Throwable $e) { $_SESSION['err']=$e->getMessage(); }
        header('Location: /admin/users/'.$id); exit;
    }
    public function toggleStatus(string $id): void {
        if (!admin_can('users.edit')) { http_response_code(403); exit; }
        db()->prepare("UPDATE users SET status = IF(status='active','disabled','active') WHERE id=?")->execute([(int)$id]);
        log_activity('user.toggle_status','user',(int)$id);
        header('Location: /admin/users/'.$id); exit;
    }
}
PHP);

w('admin/controllers/GamesController.php', <<<'PHP'
<?php
declare(strict_types=1);
class GamesController {
    public function index(): void {
        if (!admin_can('games.view')) { http_response_code(403); exit; }
        $rows = db()->query("SELECT * FROM games ORDER BY id DESC LIMIT 200")->fetchAll();
        view('games/index', ['games'=>$rows]);
    }
    public function create(): void {
        if (!admin_can('games.create')) { http_response_code(403); exit; }
        $cats = db()->query("SELECT id,name FROM categories ORDER BY name")->fetchAll();
        view('games/form', ['game'=>null, 'cats'=>$cats]);
    }
    public function edit(string $id): void {
        if (!admin_can('games.edit')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT * FROM games WHERE id=?"); $s->execute([(int)$id]);
        $g = $s->fetch(); if (!$g) { http_response_code(404); exit; }
        $cats = db()->query("SELECT id,name FROM categories ORDER BY name")->fetchAll();
        view('games/form', ['game'=>$g, 'cats'=>$cats]);
    }
    public function store(): void {
        if (!admin_can('games.create')) { http_response_code(403); exit; }
        $name = trim((string)$_POST['name']); $slug = trim((string)($_POST['slug'] ?? '')) ?: slugify($name);
        $img = null; $banner = null;
        if (!empty($_FILES['image']['name'])) $img = upload_image($_FILES['image'], 'games');
        if (!empty($_FILES['banner']['name'])) $banner = upload_image($_FILES['banner'], 'games');
        db()->prepare("INSERT INTO games (category_id,name,slug,description,image,banner,status,featured,sort_order) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([(int)($_POST['category_id'] ?? 0) ?: null, $name, $slug, $_POST['description'] ?? null, $img, $banner,
                       isset($_POST['status'])?1:0, isset($_POST['featured'])?1:0, (int)($_POST['sort_order'] ?? 0)]);
        log_activity('game.create','game',(int)db()->lastInsertId(),$name);
        header('Location: /admin/games'); exit;
    }
    public function update(string $id): void {
        if (!admin_can('games.edit')) { http_response_code(403); exit; }
        $name = trim((string)$_POST['name']); $slug = trim((string)($_POST['slug'] ?? '')) ?: slugify($name);
        $img = null; $banner = null;
        if (!empty($_FILES['image']['name'])) $img = upload_image($_FILES['image'], 'games');
        if (!empty($_FILES['banner']['name'])) $banner = upload_image($_FILES['banner'], 'games');
        $sql = "UPDATE games SET category_id=?, name=?, slug=?, description=?, status=?, featured=?, sort_order=?";
        $args = [(int)($_POST['category_id'] ?? 0) ?: null, $name, $slug, $_POST['description'] ?? null, isset($_POST['status'])?1:0, isset($_POST['featured'])?1:0, (int)($_POST['sort_order'] ?? 0)];
        if ($img) { $sql .= ", image=?"; $args[] = $img; }
        if ($banner) { $sql .= ", banner=?"; $args[] = $banner; }
        $sql .= " WHERE id=?"; $args[] = (int)$id;
        db()->prepare($sql)->execute($args);
        log_activity('game.update','game',(int)$id,$name);
        header('Location: /admin/games'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('games.delete')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM games WHERE id=?")->execute([(int)$id]);
        log_activity('game.delete','game',(int)$id);
        header('Location: /admin/games'); exit;
    }
}
PHP);

w('admin/controllers/CategoriesController.php', <<<'PHP'
<?php
declare(strict_types=1);
class CategoriesController {
    public function index(): void {
        if (!admin_can('games.view')) { http_response_code(403); exit; }
        view('categories/index', ['categories'=>db()->query("SELECT * FROM categories ORDER BY sort_order")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('games.create')) { http_response_code(403); exit; }
        $n = trim((string)$_POST['name']); $s = trim((string)($_POST['slug'] ?? '')) ?: slugify($n);
        db()->prepare("INSERT INTO categories (name,slug,status,sort_order) VALUES (?,?,?,?)")
            ->execute([$n,$s,1,(int)($_POST['sort_order'] ?? 0)]);
        header('Location: /admin/categories'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('games.delete')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM categories WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/categories'); exit;
    }
}
PHP);

w('admin/controllers/OrdersController.php', <<<'PHP'
<?php
declare(strict_types=1);
class OrdersController {
    public function index(): void {
        if (!admin_can('orders.view')) { http_response_code(403); exit; }
        $status = $_GET['status'] ?? ''; $q = trim((string)($_GET['q'] ?? ''));
        $where = []; $args = [];
        if ($status) { $where[] = "o.status = ?"; $args[] = $status; }
        if ($q) { $where[] = "(o.order_number LIKE ? OR u.email LIKE ?)"; $args[] = "%$q%"; $args[] = "%$q%"; }
        $sql = "SELECT o.*, u.name user_name, u.email user_email FROM orders o JOIN users u ON u.id=o.user_id";
        if ($where) $sql .= " WHERE " . implode(' AND ', $where);
        $sql .= " ORDER BY o.id DESC LIMIT 200";
        $s = db()->prepare($sql); $s->execute($args);
        view('orders/index', ['orders'=>$s->fetchAll(), 'status'=>$status, 'q'=>$q]);
    }
    public function show(string $id): void {
        if (!admin_can('orders.view')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT o.*, u.name user_name, u.email user_email, p.name product_name, g.name game_name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id LEFT JOIN games g ON g.id=o.game_id WHERE o.id=?");
        $s->execute([(int)$id]); $o = $s->fetch(); if (!$o) { http_response_code(404); exit; }
        $s = db()->prepare("SELECT * FROM order_status_history WHERE order_id=? ORDER BY id"); $s->execute([(int)$id]);
        view('orders/show', ['order'=>$o, 'history'=>$s->fetchAll()]);
    }
    public function updateStatus(string $id): void {
        if (!admin_can('orders.edit')) { http_response_code(403); exit; }
        $status = $_POST['status'] ?? ''; $note = trim((string)($_POST['note'] ?? ''));
        if (!in_array($status, ['pending','processing','completed','cancelled','rejected'], true)) { http_response_code(400); exit; }
        $a = auth_admin();
        db()->prepare("UPDATE orders SET status=? WHERE id=?")->execute([$status,(int)$id]);
        db()->prepare("INSERT INTO order_status_history (order_id,status,note,admin_id) VALUES (?,?,?,?)")->execute([(int)$id,$status,$note,$a['id']]);
        log_activity('order.status','order',(int)$id,"Set to $status");
        $s = db()->prepare("SELECT user_id,order_number FROM orders WHERE id=?"); $s->execute([(int)$id]);
        $o = $s->fetch();
        if ($o) NotificationService::notifyUser((int)$o['user_id'],'order_'.$status,'تحديث الطلب',"الطلب {$o['order_number']}: $status","/orders/$id");
        header('Location: /admin/orders/'.$id); exit;
    }
    public function refund(string $id): void {
        if (!admin_can('orders.edit')) { http_response_code(403); exit; }
        try { OrderService::refund((int)$id,(int)auth_admin()['id'],trim((string)($_POST['note'] ?? ''))); log_activity('order.refund','order',(int)$id); }
        catch (Throwable $e) { $_SESSION['err']=$e->getMessage(); }
        header('Location: /admin/orders/'.$id); exit;
    }
}
PHP);

w('admin/controllers/DepositsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class DepositsController {
    public function index(): void {
        if (!admin_can('deposits.view')) { http_response_code(403); exit; }
        $status = $_GET['status'] ?? '';
        $sql = "SELECT d.*, u.name user_name, u.email user_email, pm.name method_name FROM deposits d JOIN users u ON u.id=d.user_id JOIN payment_methods pm ON pm.id=d.payment_method_id";
        $args = [];
        if ($status) { $sql .= " WHERE d.status=?"; $args[] = $status; }
        $sql .= " ORDER BY d.id DESC LIMIT 200";
        $s = db()->prepare($sql); $s->execute($args);
        view('deposits/index', ['deposits'=>$s->fetchAll(), 'status'=>$status]);
    }
    public function approve(string $id): void {
        if (!admin_can('deposits.approve')) { http_response_code(403); exit; }
        try { DepositService::approve((int)$id,(int)auth_admin()['id']); log_activity('deposit.approve','deposit',(int)$id); }
        catch (Throwable $e) { $_SESSION['err']=$e->getMessage(); }
        header('Location: /admin/deposits'); exit;
    }
    public function reject(string $id): void {
        if (!admin_can('deposits.reject')) { http_response_code(403); exit; }
        try { DepositService::reject((int)$id,(int)auth_admin()['id'],trim((string)($_POST['note'] ?? ''))); log_activity('deposit.reject','deposit',(int)$id); }
        catch (Throwable $e) { $_SESSION['err']=$e->getMessage(); }
        header('Location: /admin/deposits'); exit;
    }
}
PHP);

w('admin/controllers/PaymentMethodsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class PaymentMethodsController {
    public function index(): void {
        if (!admin_can('settings.view')) { http_response_code(403); exit; }
        view('payment_methods/index', ['methods'=>db()->query("SELECT * FROM payment_methods ORDER BY sort_order")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('settings.edit')) { http_response_code(403); exit; }
        db()->prepare("INSERT INTO payment_methods (name,description,account_number,account_name,instructions,min_amount,max_amount,status,sort_order) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([trim((string)$_POST['name']), $_POST['description'] ?? null, $_POST['account_number'] ?? null, $_POST['account_name'] ?? null,
                       $_POST['instructions'] ?? null, (float)($_POST['min_amount'] ?? 0), (float)($_POST['max_amount'] ?? 100000),
                       isset($_POST['status'])?1:0, (int)($_POST['sort_order'] ?? 0)]);
        header('Location: /admin/payment-methods'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('settings.edit')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM payment_methods WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/payment-methods'); exit;
    }
}
PHP);

w('admin/controllers/CouponsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class CouponsController {
    public function index(): void {
        if (!admin_can('coupons.view')) { http_response_code(403); exit; }
        view('coupons/index', ['coupons'=>db()->query("SELECT * FROM coupons ORDER BY id DESC")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('coupons.manage')) { http_response_code(403); exit; }
        db()->prepare("INSERT INTO coupons (code,type,value,min_order,max_discount,starts_at,ends_at,usage_limit,user_usage_limit,status) VALUES (?,?,?,?,?,?,?,?,?,?)")
            ->execute([strtoupper(trim((string)$_POST['code'])), $_POST['type'] ?? 'percentage', (float)($_POST['value'] ?? 0),
                       (float)($_POST['min_order'] ?? 0), ($_POST['max_discount'] ?? '') !== '' ? (float)$_POST['max_discount'] : null,
                       $_POST['starts_at'] ?? null, $_POST['ends_at'] ?? null,
                       ($_POST['usage_limit'] ?? '') !== '' ? (int)$_POST['usage_limit'] : null,
                       (int)($_POST['user_usage_limit'] ?? 1), isset($_POST['status'])?1:0]);
        header('Location: /admin/coupons'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('coupons.manage')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM coupons WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/coupons'); exit;
    }
}
PHP);

w('admin/controllers/OffersController.php', <<<'PHP'
<?php
declare(strict_types=1);
class OffersController {
    public function index(): void {
        if (!admin_can('offers.view')) { http_response_code(403); exit; }
        view('offers/index', ['offers'=>db()->query("SELECT * FROM offers ORDER BY id DESC")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('offers.manage')) { http_response_code(403); exit; }
        db()->prepare("INSERT INTO offers (name,description,type,discount,game_id,product_id,starts_at,ends_at,status) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([trim((string)$_POST['name']), $_POST['description'] ?? null, $_POST['type'] ?? 'flash', (float)($_POST['discount'] ?? 0),
                       ($_POST['game_id'] ?? '') !== '' ? (int)$_POST['game_id'] : null,
                       ($_POST['product_id'] ?? '') !== '' ? (int)$_POST['product_id'] : null,
                       $_POST['starts_at'] ?? null, $_POST['ends_at'] ?? null, isset($_POST['status'])?1:0]);
        header('Location: /admin/offers'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('offers.manage')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM offers WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/offers'); exit;
    }
}
PHP);

w('admin/controllers/TicketsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class TicketsController {
    public function index(): void {
        if (!admin_can('tickets.view')) { http_response_code(403); exit; }
        $s = db()->query("SELECT t.*, u.name user_name FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200");
        view('tickets/index', ['tickets'=>$s->fetchAll()]);
    }
    public function show(string $id): void {
        if (!admin_can('tickets.view')) { http_response_code(403); exit; }
        $s = db()->prepare("SELECT t.*, u.name user_name FROM tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?"); $s->execute([(int)$id]);
        $t = $s->fetch(); if (!$t) { http_response_code(404); exit; }
        $s = db()->prepare("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id"); $s->execute([(int)$id]);
        view('tickets/show', ['ticket'=>$t, 'messages'=>$s->fetchAll()]);
    }
    public function reply(string $id): void {
        if (!admin_can('tickets.reply')) { http_response_code(403); exit; }
        $msg = trim((string)($_POST['message'] ?? '')); if ($msg==='') { header('Location: /admin/tickets/'.$id); exit; }
        db()->prepare("INSERT INTO ticket_messages (ticket_id,sender_type,sender_id,message) VALUES (?,'admin',?,?)")
            ->execute([(int)$id,(int)auth_admin()['id'],$msg]);
        db()->prepare("UPDATE tickets SET status='answered' WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/tickets/'.$id); exit;
    }
}
PHP);

w('admin/controllers/BannersController.php', <<<'PHP'
<?php
declare(strict_types=1);
class BannersController {
    public function index(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        view('banners/index', ['banners'=>db()->query("SELECT * FROM banners ORDER BY sort_order")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        $img = upload_image($_FILES['image'], 'banners');
        db()->prepare("INSERT INTO banners (title,description,image,button_text,button_url,starts_at,ends_at,status,sort_order) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([trim((string)$_POST['title']), $_POST['description'] ?? null, $img, $_POST['button_text'] ?? null, $_POST['button_url'] ?? null,
                       $_POST['starts_at'] ?? null, $_POST['ends_at'] ?? null, isset($_POST['status'])?1:0, (int)($_POST['sort_order'] ?? 0)]);
        header('Location: /admin/banners'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM banners WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/banners'); exit;
    }
}
PHP);

w('admin/controllers/PagesController.php', <<<'PHP'
<?php
declare(strict_types=1);
class PagesController {
    public function index(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        view('pages/index', ['pages'=>db()->query("SELECT * FROM pages ORDER BY id DESC")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        $t = trim((string)$_POST['title']); $s = trim((string)($_POST['slug'] ?? '')) ?: slugify($t);
        db()->prepare("INSERT INTO pages (title,slug,content,status) VALUES (?,?,?,?)")
            ->execute([$t, $s, $_POST['content'] ?? '', isset($_POST['status'])?1:0]);
        header('Location: /admin/pages'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM pages WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/pages'); exit;
    }
}
PHP);

w('admin/controllers/SocialController.php', <<<'PHP'
<?php
declare(strict_types=1);
class SocialController {
    public function index(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        view('social/index', ['links'=>db()->query("SELECT * FROM social_links ORDER BY sort_order")->fetchAll()]);
    }
    public function store(): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        db()->prepare("INSERT INTO social_links (name,icon,url,status,sort_order) VALUES (?,?,?,?,?)")
            ->execute([trim((string)$_POST['name']), $_POST['icon'] ?? null, trim((string)$_POST['url']),
                       isset($_POST['status'])?1:0, (int)($_POST['sort_order'] ?? 0)]);
        header('Location: /admin/social'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('content.manage')) { http_response_code(403); exit; }
        db()->prepare("DELETE FROM social_links WHERE id=?")->execute([(int)$id]);
        header('Location: /admin/social'); exit;
    }
}
PHP);

w('admin/controllers/AdminsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class AdminsController {
    public function index(): void {
        if (!admin_can('admins.view')) { http_response_code(403); exit; }
        $admins = db()->query("SELECT a.*, r.name role_name FROM admins a JOIN roles r ON r.id=a.role_id ORDER BY a.id DESC")->fetchAll();
        $roles = db()->query("SELECT * FROM roles ORDER BY id")->fetchAll();
        view('admins/index', ['admins'=>$admins, 'roles'=>$roles]);
    }
    public function store(): void {
        if (!admin_can('admins.manage')) { http_response_code(403); exit; }
        db()->prepare("INSERT INTO admins (name,email,password,role_id,status) VALUES (?,?,?,?,?)")
            ->execute([trim((string)$_POST['name']), trim((string)$_POST['email']), hash_password((string)$_POST['password']),
                       (int)$_POST['role_id'], $_POST['status'] ?? 'active']);
        log_activity('admin.create','admin',(int)db()->lastInsertId());
        header('Location: /admin/admins'); exit;
    }
    public function destroy(string $id): void {
        if (!admin_can('admins.manage')) { http_response_code(403); exit; }
        if ((int)$id === (int)auth_admin()['id']) { $_SESSION['err']='Cannot delete yourself'; header('Location: /admin/admins'); exit; }
        db()->prepare("DELETE FROM admins WHERE id=?")->execute([(int)$id]);
        log_activity('admin.delete','admin',(int)$id);
        header('Location: /admin/admins'); exit;
    }
}
PHP);

w('admin/controllers/RolesController.php', <<<'PHP'
<?php
declare(strict_types=1);
class RolesController {
    public function index(): void {
        if (!admin_can('roles.manage')) { http_response_code(403); exit; }
        $roles = db()->query("SELECT * FROM roles ORDER BY id")->fetchAll();
        $perms = db()->query("SELECT * FROM permissions ORDER BY `group`, slug")->fetchAll();
        $map = [];
        foreach (db()->query("SELECT role_id, permission_id FROM role_permissions")->fetchAll() as $r) $map[$r['role_id']][] = (int)$r['permission_id'];
        view('roles/index', ['roles'=>$roles, 'perms'=>$perms, 'map'=>$map]);
    }
    public function update(string $id): void {
        if (!admin_can('roles.manage')) { http_response_code(403); exit; }
        $ids = array_map('intval', $_POST['permission_ids'] ?? []);
        $pdo = db(); $pdo->beginTransaction();
        try {
            $pdo->prepare("DELETE FROM role_permissions WHERE role_id=?")->execute([(int)$id]);
            $ins = $pdo->prepare("INSERT INTO role_permissions (role_id,permission_id) VALUES (?,?)");
            foreach ($ids as $pid) $ins->execute([(int)$id,$pid]);
            $pdo->commit(); log_activity('role.perms','role',(int)$id);
        } catch (Throwable $e) { $pdo->rollBack(); $_SESSION['err']=$e->getMessage(); }
        header('Location: /admin/roles'); exit;
    }
}
PHP);

w('admin/controllers/LogsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class LogsController {
    public function index(): void {
        if (!admin_can('logs.view')) { http_response_code(403); exit; }
        $rows = db()->query("SELECT al.*, a.name admin_name FROM activity_logs al LEFT JOIN admins a ON a.id=al.admin_id ORDER BY al.id DESC LIMIT 500")->fetchAll();
        view('logs/index', ['logs'=>$rows]);
    }
}
PHP);

w('admin/controllers/SettingsController.php', <<<'PHP'
<?php
declare(strict_types=1);
class SettingsController {
    public function index(): void {
        if (!admin_can('settings.view')) { http_response_code(403); exit; }
        view('settings/index', ['groups'=>Setting::allGrouped()]);
    }
    public function save(): void {
        if (!admin_can('settings.edit')) { http_response_code(403); exit; }
        foreach ($_POST as $k => $v) {
            if ($k === '_csrf') continue;
            if (is_array($v)) $v = json_encode($v);
            Setting::set($k, (string)$v);
        }
        foreach (['logo','favicon','og_image'] as $f) {
            if (!empty($_FILES[$f]['name'])) {
                try { Setting::set($f, upload_image($_FILES[$f], 'settings')); } catch (Throwable $e) {}
            }
        }
        log_activity('settings.save');
        $_SESSION['msg'] = 'تم الحفظ';
        header('Location: /admin/settings'); exit;
    }
}
PHP);

w('admin/controllers/WalletAdminController.php', <<<'PHP'
<?php
declare(strict_types=1);
class WalletAdminController {
    public function index(): void {
        if (!admin_can('wallet.view')) { http_response_code(403); exit; }
        $rows = db()->query("SELECT wt.*, u.name user_name FROM wallet_transactions wt JOIN users u ON u.id=wt.user_id ORDER BY wt.id DESC LIMIT 300")->fetchAll();
        view('wallet/index', ['tx'=>$rows]);
    }
}
PHP);

// =========================================================
// 9) ADMIN VIEWS
// =========================================================
w('admin/views/layout.php', <<<'PHP'
<?php $admin = auth_admin(); $siteName = setting('site_name','The Witcher Store'); ?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin · <?= e($siteName) ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
body{background:#0B0D0F;color:#eaeaea}
.sidebar{background:#131619;min-height:100vh;padding-top:20px;position:fixed;width:250px;top:0;right:0;overflow-y:auto}
.sidebar a{display:block;color:#aab;padding:9px 18px;text-decoration:none;border-radius:8px;margin:2px 8px;font-size:.94rem}
.sidebar a:hover{background:#1c2026;color:#BEEE11}
.main{margin-right:250px;padding:25px}
.card{background:#181C20;border:1px solid #23272e;color:#eaeaea}
.table{color:#eaeaea}
.btn-primary{background:#BEEE11;border-color:#BEEE11;color:#0B0D0F;font-weight:700}
.badge-ok{background:#43A047}.badge-bad{background:#E53935}.badge-warn{background:#FFB300;color:#000}
</style>
</head>
<body>
<div class="sidebar">
  <h4 class="text-center mb-3" style="color:#BEEE11">Witcher Admin</h4>
  <a href="/admin"><i class="bi bi-speedometer2"></i> Dashboard</a>
  <a href="/admin/users"><i class="bi bi-people"></i> Users</a>
  <a href="/admin/games"><i class="bi bi-controller"></i> Games</a>
  <a href="/admin/categories"><i class="bi bi-tags"></i> Categories</a>
  <a href="/admin/products"><i class="bi bi-box-seam"></i> Products</a>
  <a href="/admin/orders"><i class="bi bi-bag-check"></i> Orders</a>
  <a href="/admin/deposits"><i class="bi bi-cash-coin"></i> Deposits</a>
  <a href="/admin/wallet"><i class="bi bi-wallet2"></i> Wallet</a>
  <a href="/admin/payment-methods"><i class="bi bi-credit-card"></i> Payment Methods</a>
  <a href="/admin/coupons"><i class="bi bi-ticket-perforated"></i> Coupons</a>
  <a href="/admin/offers"><i class="bi bi-percent"></i> Offers</a>
  <a href="/admin/tickets"><i class="bi bi-life-preserver"></i> Tickets</a>
  <a href="/admin/banners"><i class="bi bi-image"></i> Banners</a>
  <a href="/admin/pages"><i class="bi bi-file-text"></i> Pages</a>
  <a href="/admin/social"><i class="bi bi-share"></i> Social</a>
  <a href="/admin/admins"><i class="bi bi-person-badge"></i> Admins</a>
  <a href="/admin/roles"><i class="bi bi-shield-lock"></i> Roles</a>
  <a href="/admin/logs"><i class="bi bi-list-check"></i> Logs</a>
  <a href="/admin/settings"><i class="bi bi-gear"></i> Settings</a>
  <hr class="text-secondary">
  <a href="/admin/logout" class="text-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
</div>
<div class="main">
  <?php if (!empty($_SESSION['msg'])): ?><div class="alert alert-success"><?= e($_SESSION['msg']); unset($_SESSION['msg']); ?></div><?php endif; ?>
  <?php if (!empty($_SESSION['err'])): ?><div class="alert alert-danger"><?= e($_SESSION['err']); unset($_SESSION['err']); ?></div><?php endif; ?>
  <?= $content ?? '' ?>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
PHP);

w('admin/views/dashboard.php', <<<'PHP'
<?php ob_start(); ?>
<h1>Dashboard</h1>
<div class="row g-3 mb-4">
<?php foreach ($stats as $k=>$v): ?>
  <div class="col-md-3"><div class="card p-3"><div class="text-muted small"><?= e($k) ?></div><div class="fs-4 fw-bold"><?= is_numeric($v) ? number_format((float)$v,2) : e((string)$v) ?></div></div></div>
<?php endforeach; ?>
</div>
<div class="row g-3">
  <div class="col-md-6"><div class="card p-3"><h5>Top Games</h5><ul><?php foreach ($topGames as $g): ?><li><?= e($g['name']) ?> — <?= (int)$g['c'] ?></li><?php endforeach; ?></ul></div></div>
  <div class="col-md-6"><div class="card p-3"><h5>Top Products</h5><ul><?php foreach ($topProducts as $p): ?><li><?= e($p['name']) ?> — <?= (int)$p['c'] ?></li><?php endforeach; ?></ul></div></div>
</div>
<?php $content = ob_get_clean(); require __DIR__.'/layout.php'; PHP);

w('admin/views/auth/login.php', <<<'PHP'
<?php ob_start(); ?>
<div class="row justify-content-center"><div class="col-md-5">
<form method="post" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <h3 class="mb-3" style="color:#BEEE11">Admin Login</h3>
  <?php if (!empty($_SESSION['err'])): ?><div class="alert alert-danger"><?= e($_SESSION['err']); unset($_SESSION['err']); ?></div><?php endif; ?>
  <div class="mb-3"><label>Email</label><input class="form-control" type="email" name="email" required></div>
  <div class="mb-3"><label>Password</label><input class="form-control" type="password" name="password" required></div>
  <button class="btn btn-primary">Login</button>
</form></div></div>
<?php $content = ob_get_clean(); require __DIR__.'/layout.php'; PHP);

w('admin/views/products/index.php', <<<'PHP'
<?php ob_start(); ?>
<div class="d-flex justify-content-between mb-3"><h2>المنتجات</h2><a class="btn btn-primary" href="/admin/products/create">+ جديد</a></div>
<table class="table table-dark table-hover"><thead><tr><th>#</th><th>الاسم</th><th>اللعبة</th><th>السعر</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($products as $p): ?>
<tr><td><?= (int)$p['id'] ?></td><td><?= e($p['name']) ?></td><td><?= e($p['game_name']) ?></td><td><?= number_format((float)$p['price'],2) ?></td>
<td><?= $p['status'] ? 'نشط' : 'معطل' ?></td>
<td><a class="btn btn-sm btn-outline-light" href="/admin/products/<?= (int)$p['id'] ?>/edit">تعديل</a>
<a class="btn btn-sm btn-outline-info" href="/admin/products/<?= (int)$p['id'] ?>/fields">حقول</a>
<form method="post" action="/admin/products/<?= (int)$p['id'] ?>/delete" class="d-inline" onsubmit="return confirm('تأكيد؟')"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/products/form.php', <<<'PHP'
<?php ob_start(); $isEdit = (bool)$product; ?>
<h2><?= $isEdit ? 'تعديل' : 'منتج جديد' ?></h2>
<form method="post" action="<?= $isEdit ? '/admin/products/'.(int)$product['id'] : '/admin/products' ?>" enctype="multipart/form-data" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-3">
    <div class="col-md-6"><label>اللعبة</label><select class="form-select" name="game_id" required>
      <?php foreach ($games as $g): ?><option value="<?= (int)$g['id'] ?>" <?= $isEdit && (int)$product['game_id']===(int)$g['id']?'selected':'' ?>><?= e($g['name']) ?></option><?php endforeach; ?>
    </select></div>
    <div class="col-md-6"><label>الاسم</label><input class="form-control" name="name" required value="<?= e($product['name'] ?? '') ?>"></div>
    <div class="col-md-6"><label>Slug</label><input class="form-control" name="slug" value="<?= e($product['slug'] ?? '') ?>"></div>
    <div class="col-md-3"><label>السعر</label><input class="form-control" type="number" step="0.01" name="price" value="<?= e((string)($product['price'] ?? 0)) ?>"></div>
    <div class="col-md-3"><label>السعر القديم</label><input class="form-control" type="number" step="0.01" name="old_price" value="<?= e((string)($product['old_price'] ?? '')) ?>"></div>
    <div class="col-md-3"><label>سعر التكلفة</label><input class="form-control" type="number" step="0.01" name="cost_price" value="<?= e((string)($product['cost_price'] ?? '')) ?>"></div>
    <div class="col-md-3"><label>الخصم</label><input class="form-control" type="number" step="0.01" name="discount" value="<?= e((string)($product['discount'] ?? 0)) ?>"></div>
    <div class="col-md-3"><label>SKU</label><input class="form-control" name="sku" value="<?= e($product['sku'] ?? '') ?>"></div>
    <div class="col-md-3"><label>Stock</label><input class="form-control" type="number" name="stock" value="<?= e((string)($product['stock'] ?? -1)) ?>"></div>
    <div class="col-md-3"><label>Sort</label><input class="form-control" type="number" name="sort_order" value="<?= e((string)($product['sort_order'] ?? 0)) ?>"></div>
    <div class="col-md-3">
      <div class="form-check"><input class="form-check-input" type="checkbox" name="status" value="1" <?= !$isEdit || $product['status'] ? 'checked' : '' ?>><label class="form-check-label">نشط</label></div>
      <div class="form-check"><input class="form-check-input" type="checkbox" name="featured" value="1" <?= $isEdit && $product['featured'] ? 'checked' : '' ?>><label class="form-check-label">مميز</label></div>
    </div>
    <div class="col-12"><label>الوصف</label><textarea class="form-control" name="description" rows="4"><?= e($product['description'] ?? '') ?></textarea></div>
    <div class="col-md-6"><label>الصورة</label><input class="form-control" type="file" name="image" accept="image/*"></div>
  </div>
  <div class="mt-3"><button class="btn btn-primary">حفظ</button> <a class="btn btn-outline-light" href="/admin/products">إلغاء</a></div>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/products/fields.php', <<<'PHP'
<?php ob_start(); ?>
<h2>حقول المنتج: <?= e($product['name']) ?></h2>
<form method="post" action="/admin/products/<?= (int)$product['id'] ?>/fields" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <table class="table table-dark" id="ft"><thead><tr><th>اسم</th><th>عنوان</th><th>نوع</th><th>خيارات</th><th>Placeholder</th><th>مطلوب</th></tr></thead><tbody>
  <?php $rows = $fields ?: [['field_name'=>'','field_label'=>'','field_type'=>'text','field_options'=>'','placeholder'=>'','required'=>1]]; ?>
  <?php foreach ($rows as $i=>$f): ?>
  <tr>
    <td><input class="form-control" name="field_name[]" value="<?= e($f['field_name']) ?>"></td>
    <td><input class="form-control" name="field_label[]" value="<?= e($f['field_label']) ?>"></td>
    <td><select class="form-select" name="field_type[]"><?php foreach (['text','number','email','select','textarea'] as $t): ?><option <?= $f['field_type']===$t?'selected':'' ?>><?= $t ?></option><?php endforeach; ?></select></td>
    <td><input class="form-control" name="field_options[]" value="<?= e($f['field_options'] ?? '') ?>"></td>
    <td><input class="form-control" name="placeholder[]" value="<?= e($f['placeholder'] ?? '') ?>"></td>
    <td><input class="form-check-input" type="checkbox" name="required[<?= $i ?>]" <?= !empty($f['required'])?'checked':'' ?>></td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <button class="btn btn-primary">حفظ</button>
  <button type="button" class="btn btn-outline-light" onclick="addRow()">+ حقل</button>
</form>
<script>function addRow(){const t=document.querySelector('#ft tbody');const i=t.children.length;
t.insertAdjacentHTML('beforeend',`<tr><td><input class="form-control" name="field_name[]"></td><td><input class="form-control" name="field_label[]"></td><td><select class="form-select" name="field_type[]"><option>text</option><option>number</option><option>email</option><option>select</option><option>textarea</option></select></td><td><input class="form-control" name="field_options[]"></td><td><input class="form-control" name="placeholder[]"></td><td><input class="form-check-input" type="checkbox" name="required[${i}]"></td></tr>`);}</script>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/users/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>المستخدمون</h2>
<form class="mb-3"><input class="form-control" name="q" placeholder="بحث" value="<?= e($q) ?>"></form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>البريد</th><th>الرصيد</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($users as $u): ?>
<tr><td><?= (int)$u['id'] ?></td><td><?= e($u['name']) ?></td><td><?= e($u['email']) ?></td><td><?= number_format((float)($u['balance'] ?? 0),2) ?></td><td><?= e($u['status']) ?></td>
<td><a class="btn btn-sm btn-outline-light" href="/admin/users/<?= (int)$u['id'] ?>">عرض</a></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/users/show.php', <<<'PHP'
<?php ob_start(); ?>
<h2><?= e($user['name']) ?> <small class="text-muted"><?= e($user['email']) ?></small></h2>
<div class="row g-3 mb-3">
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">الرصيد</div><div class="fs-4"><?= number_format((float)$wallet['balance'],2) ?></div></div></div>
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">إجمالي الإيداع</div><div class="fs-4"><?= number_format((float)$wallet['total_deposited'],2) ?></div></div></div>
  <div class="col-md-4"><div class="card p-3"><div class="text-muted">إجمالي الإنفاق</div><div class="fs-4"><?= number_format((float)$wallet['total_spent'],2) ?></div></div></div>
</div>
<form method="post" action="/admin/users/<?= (int)$user['id'] ?>/wallet" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-3"><select class="form-select" name="type"><option value="credit">إضافة</option><option value="debit">خصم</option></select></div>
    <div class="col-md-3"><input class="form-control" type="number" step="0.01" name="amount" placeholder="المبلغ" required></div>
    <div class="col-md-4"><input class="form-control" name="reason" placeholder="السبب"></div>
    <div class="col-md-2"><button class="btn btn-primary w-100">تنفيذ</button></div>
  </div>
</form>
<form method="post" action="/admin/users/<?= (int)$user['id'] ?>/status" class="mb-3"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-warning">تبديل الحالة</button></form>
<h4>آخر المعاملات</h4>
<table class="table table-dark"><thead><tr><th>النوع</th><th>المبلغ</th><th>بعد</th><th>التاريخ</th></tr></thead><tbody>
<?php foreach ($tx as $t): ?><tr><td><?= e($t['type']) ?></td><td><?= number_format((float)$t['amount'],2) ?></td><td><?= number_format((float)$t['balance_after'],2) ?></td><td><?= e($t['created_at']) ?></td></tr><?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/games/index.php', <<<'PHP'
<?php ob_start(); ?>
<div class="d-flex justify-content-between mb-3"><h2>الألعاب</h2><a class="btn btn-primary" href="/admin/games/create">+ جديد</a></div>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>Slug</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($games as $g): ?>
<tr><td><?= (int)$g['id'] ?></td><td><?= e($g['name']) ?></td><td><?= e($g['slug']) ?></td><td><?= $g['status']?'نشط':'معطل' ?></td>
<td><a class="btn btn-sm btn-outline-light" href="/admin/games/<?= (int)$g['id'] ?>/edit">تعديل</a>
<form method="post" action="/admin/games/<?= (int)$g['id'] ?>/delete" class="d-inline" onsubmit="return confirm('تأكيد؟')"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/games/form.php', <<<'PHP'
<?php ob_start(); $isEdit = (bool)$game; ?>
<h2><?= $isEdit ? 'تعديل' : 'لعبة جديدة' ?></h2>
<form method="post" action="<?= $isEdit ? '/admin/games/'.(int)$game['id'] : '/admin/games' ?>" enctype="multipart/form-data" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-3">
    <div class="col-md-6"><label>الفئة</label><select class="form-select" name="category_id">
      <option value="">— بدون —</option>
      <?php foreach ($cats as $c): ?><option value="<?= (int)$c['id'] ?>" <?= $isEdit && (int)$game['category_id']===(int)$c['id']?'selected':'' ?>><?= e($c['name']) ?></option><?php endforeach; ?>
    </select></div>
    <div class="col-md-6"><label>الاسم</label><input class="form-control" name="name" required value="<?= e($game['name'] ?? '') ?>"></div>
    <div class="col-md-6"><label>Slug</label><input class="form-control" name="slug" value="<?= e($game['slug'] ?? '') ?>"></div>
    <div class="col-md-3"><label>ترتيب</label><input class="form-control" type="number" name="sort_order" value="<?= e((string)($game['sort_order'] ?? 0)) ?>"></div>
    <div class="col-md-3">
      <div class="form-check"><input class="form-check-input" type="checkbox" name="status" value="1" <?= !$isEdit || $game['status'] ? 'checked' : '' ?>><label>نشط</label></div>
      <div class="form-check"><input class="form-check-input" type="checkbox" name="featured" value="1" <?= $isEdit && $game['featured'] ? 'checked' : '' ?>><label>مميز</label></div>
    </div>
    <div class="col-12"><label>الوصف</label><textarea class="form-control" name="description" rows="3"><?= e($game['description'] ?? '') ?></textarea></div>
    <div class="col-md-6"><label>الصورة</label><input class="form-control" type="file" name="image"></div>
    <div class="col-md-6"><label>البنر</label><input class="form-control" type="file" name="banner"></div>
  </div>
  <div class="mt-3"><button class="btn btn-primary">حفظ</button> <a class="btn btn-outline-light" href="/admin/games">إلغاء</a></div>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/orders/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الطلبات</h2>
<form class="mb-3 row g-2">
  <div class="col-md-3"><select class="form-select" name="status">
    <option value="">— الحالة —</option>
    <?php foreach (['pending','processing','completed','cancelled','rejected','refunded'] as $s): ?>
      <option <?= $status===$s?'selected':'' ?>><?= $s ?></option>
    <?php endforeach; ?>
  </select></div>
  <div class="col-md-3"><input class="form-control" name="q" value="<?= e($q) ?>" placeholder="بحث"></div>
  <div class="col-md-2"><button class="btn btn-primary">بحث</button></div>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الرقم</th><th>المستخدم</th><th>المنتج</th><th>المبلغ</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($orders as $o): ?>
<tr><td><?= (int)$o['id'] ?></td><td><?= e($o['order_number']) ?></td><td><?= e($o['user_name']) ?></td><td><?= e($o['product_name'] ?? '—') ?></td>
<td><?= number_format((float)$o['final_price'],2) ?></td><td><?= e($o['status']) ?></td>
<td><a class="btn btn-sm btn-outline-light" href="/admin/orders/<?= (int)$o['id'] ?>">عرض</a></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/orders/show.php', <<<'PHP'
<?php ob_start(); ?>
<h2>طلب <?= e($order['order_number']) ?></h2>
<div class="card p-3 mb-3">
  <div>المستخدم: <?= e($order['user_name']) ?> — <?= e($order['user_email']) ?></div>
  <div>المنتج: <?= e($order['product_name'] ?? '—') ?></div>
  <div>المبلغ: <?= number_format((float)$order['final_price'],2) ?></div>
  <div>الحالة الحالية: <b><?= e($order['status']) ?></b></div>
  <div class="mt-2"><b>بيانات العميل:</b> <pre><?= e((string)$order['customer_data']) ?></pre></div>
</div>
<form method="post" action="/admin/orders/<?= (int)$order['id'] ?>/status" class="card p-3 mb-2">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-3"><select class="form-select" name="status">
      <?php foreach (['pending','processing','completed','cancelled','rejected'] as $s): ?><option <?= $order['status']===$s?'selected':'' ?>><?= $s ?></option><?php endforeach; ?>
    </select></div>
    <div class="col-md-6"><input class="form-control" name="note" placeholder="ملاحظة"></div>
    <div class="col-md-3"><button class="btn btn-primary w-100">تحديث</button></div>
  </div>
</form>
<form method="post" action="/admin/orders/<?= (int)$order['id'] ?>/refund" onsubmit="return confirm('تأكيد الاسترجاع؟')">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <input class="form-control mb-2" name="note" placeholder="سبب الاسترجاع">
  <button class="btn btn-danger">استرجاع المبلغ للمحفظة</button>
</form>
<h4 class="mt-3">سجل الحالة</h4>
<ul><?php foreach ($history as $h): ?><li><?= e($h['status']) ?> — <?= e($h['created_at']) ?> <?= $h['note']?'('.e($h['note']).')':'' ?></li><?php endforeach; ?></ul>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/deposits/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الإيداعات</h2>
<form class="mb-3"><select name="status" class="form-select d-inline-block" style="width:200px" onchange="this.form.submit()">
  <option value="">— الحالة —</option>
  <?php foreach (['pending','approved','rejected'] as $s): ?><option <?= $status===$s?'selected':'' ?>><?= $s ?></option><?php endforeach; ?>
</select></form>
<table class="table table-dark"><thead><tr><th>#</th><th>المستخدم</th><th>الطريقة</th><th>المبلغ</th><th>TX</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($deposits as $d): ?>
<tr><td><?= (int)$d['id'] ?></td><td><?= e($d['user_name']) ?></td><td><?= e($d['method_name']) ?></td><td><?= number_format((float)$d['amount'],2) ?></td>
<td><?= e($d['transaction_id']) ?></td><td><?= e($d['status']) ?></td>
<td>
<?php if ($d['status']==='pending'): ?>
  <form method="post" action="/admin/deposits/<?= (int)$d['id'] ?>/approve" class="d-inline"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-success" onclick="return confirm('قبول؟')">قبول</button></form>
  <form method="post" action="/admin/deposits/<?= (int)$d['id'] ?>/reject" class="d-inline"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><input type="hidden" name="note" value="rejected"><button class="btn btn-sm btn-danger" onclick="return confirm('رفض؟')">رفض</button></form>
<?php endif; ?>
<?php if ($d['screenshot']): ?><a class="btn btn-sm btn-outline-info" target="_blank" href="<?= url('uploads/'.$d['screenshot']) ?>">إيصال</a><?php endif; ?>
</td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/settings/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الإعدادات</h2>
<form method="post" enctype="multipart/form-data" class="card p-4">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <?php foreach ($groups as $group => $rows): ?>
    <h5 class="mt-3"><?= e($group) ?></h5>
    <?php foreach ($rows as $r): ?>
      <div class="row g-2 mb-2 align-items-center">
        <label class="col-md-3"><?= e($r['key']) ?></label>
        <div class="col-md-9"><input class="form-control" name="<?= e($r['key']) ?>" value="<?= e($r['value']) ?>"></div>
      </div>
    <?php endforeach; ?>
  <?php endforeach; ?>
  <div class="row g-2 mt-3">
    <div class="col-md-4"><label>Logo</label><input class="form-control" type="file" name="logo" accept="image/*"></div>
    <div class="col-md-4"><label>Favicon</label><input class="form-control" type="file" name="favicon" accept="image/*"></div>
  </div>
  <button class="btn btn-primary mt-3">حفظ</button>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/logs/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>سجل النشاط</h2>
<table class="table table-dark"><thead><tr><th>#</th><th>المشرف</th><th>الإجراء</th><th>الهدف</th><th>الوصف</th><th>IP</th><th>التاريخ</th></tr></thead><tbody>
<?php foreach ($logs as $l): ?>
<tr><td><?= (int)$l['id'] ?></td><td><?= e($l['admin_name'] ?? '—') ?></td><td><?= e($l['action']) ?></td><td><?= e(($l['target_type'] ?? '').'#'.($l['target_id'] ?? '')) ?></td><td><?= e($l['description'] ?? '') ?></td><td><?= e($l['ip_address'] ?? '') ?></td><td><?= e($l['created_at']) ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/coupons/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الكوبونات</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-2"><input class="form-control" name="code" placeholder="CODE" required></div>
    <div class="col-md-2"><select class="form-select" name="type"><option value="percentage">%</option><option value="fixed">Fixed</option></select></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="value" placeholder="Value" required></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="min_order" placeholder="Min"></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="max_discount" placeholder="Max Disc"></div>
    <div class="col-md-2"><input class="form-control" type="date" name="ends_at"></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الكود</th><th>النوع</th><th>القيمة</th><th>الاستخدام</th><th></th></tr></thead><tbody>
<?php foreach ($coupons as $c): ?>
<tr><td><?= (int)$c['id'] ?></td><td><?= e($c['code']) ?></td><td><?= e($c['type']) ?></td><td><?= e((string)$c['value']) ?></td><td><?= (int)$c['used_count'] ?> / <?= e((string)($c['usage_limit'] ?? '∞')) ?></td>
<td><form method="post" action="/admin/coupons/<?= (int)$c['id'] ?>/delete" onsubmit="return confirm('تأكيد؟')"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/offers/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>العروض</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-3"><input class="form-control" name="name" placeholder="الاسم" required></div>
    <div class="col-md-2"><select class="form-select" name="type"><option value="flash">Flash</option><option value="game">Game</option><option value="product">Product</option></select></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="discount" placeholder="Discount"></div>
    <div class="col-md-2"><input class="form-control" type="date" name="starts_at"></div>
    <div class="col-md-2"><input class="form-control" type="date" name="ends_at"></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>النوع</th><th>الخصم</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($offers as $o): ?>
<tr><td><?= (int)$o['id'] ?></td><td><?= e($o['name']) ?></td><td><?= e($o['type']) ?></td><td><?= e((string)$o['discount']) ?></td><td><?= $o['status']?'نشط':'معطل' ?></td>
<td><form method="post" action="/admin/offers/<?= (int)$o['id'] ?>/delete" onsubmit="return confirm('تأكيد؟')"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/tickets/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>التذاكر</h2>
<table class="table table-dark"><thead><tr><th>#</th><th>المستخدم</th><th>الموضوع</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($tickets as $t): ?>
<tr><td><?= (int)$t['id'] ?></td><td><?= e($t['user_name']) ?></td><td><?= e($t['subject']) ?></td><td><?= e($t['status']) ?></td>
<td><a class="btn btn-sm btn-outline-light" href="/admin/tickets/<?= (int)$t['id'] ?>">عرض</a></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/tickets/show.php', <<<'PHP'
<?php ob_start(); ?>
<h2>تذكرة #<?= (int)$ticket['id'] ?>: <?= e($ticket['subject']) ?></h2>
<div class="mb-3"><?php foreach ($messages as $m): ?>
  <div class="card p-3 mb-2"><div class="small text-muted"><?= e($m['sender_type']) ?> — <?= e($m['created_at']) ?></div><div><?= nl2br(e($m['message'])) ?></div></div>
<?php endforeach; ?></div>
<form method="post" action="/admin/tickets/<?= (int)$ticket['id'] ?>/reply" class="card p-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <textarea class="form-control mb-2" name="message" rows="3" required></textarea>
  <button class="btn btn-primary">رد</button>
</form>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/banners/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>البنرات</h2>
<form method="post" enctype="multipart/form-data" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-3"><input class="form-control" name="title" placeholder="العنوان" required></div>
    <div class="col-md-3"><input class="form-control" name="button_text" placeholder="نص الزر"></div>
    <div class="col-md-3"><input class="form-control" name="button_url" placeholder="URL"></div>
    <div class="col-md-3"><input class="form-control" type="file" name="image" required></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>العنوان</th><th>الصورة</th><th></th></tr></thead><tbody>
<?php foreach ($banners as $b): ?>
<tr><td><?= (int)$b['id'] ?></td><td><?= e($b['title']) ?></td><td><img src="<?= url('uploads/'.$b['image']) ?>" height="40"></td>
<td><form method="post" action="/admin/banners/<?= (int)$b['id'] ?>/delete"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/pages/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الصفحات</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-3"><input class="form-control" name="title" placeholder="العنوان" required></div>
    <div class="col-md-3"><input class="form-control" name="slug" placeholder="slug"></div>
    <div class="col-md-6"><input class="form-control" name="content" placeholder="HTML"></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>العنوان</th><th>Slug</th><th></th></tr></thead><tbody>
<?php foreach ($pages as $p): ?>
<tr><td><?= (int)$p['id'] ?></td><td><?= e($p['title']) ?></td><td><?= e($p['slug']) ?></td>
<td><form method="post" action="/admin/pages/<?= (int)$p['id'] ?>/delete"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/social/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>السوشيال</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-2"><input class="form-control" name="name" placeholder="Name" required></div>
    <div class="col-md-2"><input class="form-control" name="icon" placeholder="bootstrap icon"></div>
    <div class="col-md-5"><input class="form-control" name="url" placeholder="URL" required></div>
    <div class="col-md-2"><input class="form-control" type="number" name="sort_order" placeholder="Sort"></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>URL</th><th></th></tr></thead><tbody>
<?php foreach ($links as $l): ?>
<tr><td><?= (int)$l['id'] ?></td><td><?= e($l['name']) ?></td><td><?= e($l['url']) ?></td>
<td><form method="post" action="/admin/social/<?= (int)$l['id'] ?>/delete"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/admins/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>المشرفون</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-2"><input class="form-control" name="name" placeholder="Name" required></div>
    <div class="col-md-3"><input class="form-control" type="email" name="email" placeholder="Email" required></div>
    <div class="col-md-3"><input class="form-control" type="password" name="password" placeholder="Password" required></div>
    <div class="col-md-2"><select class="form-select" name="role_id"><?php foreach ($roles as $r): ?><option value="<?= (int)$r['id'] ?>"><?= e($r['name']) ?></option><?php endforeach; ?></select></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>البريد</th><th>الدور</th><th>الحالة</th><th></th></tr></thead><tbody>
<?php foreach ($admins as $a): ?>
<tr><td><?= (int)$a['id'] ?></td><td><?= e($a['name']) ?></td><td><?= e($a['email']) ?></td><td><?= e($a['role_name']) ?></td><td><?= e($a['status']) ?></td>
<td><form method="post" action="/admin/admins/<?= (int)$a['id'] ?>/delete" onsubmit="return confirm('تأكيد؟')"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/roles/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الأدوار والصلاحيات</h2>
<?php foreach ($roles as $role): ?>
<div class="card p-3 mb-3">
  <h5><?= e($role['name']) ?> <?= $role['is_super'] ? '(Super)' : '' ?></h5>
  <form method="post" action="/admin/roles/<?= (int)$role['id'] ?>">
    <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
    <div class="row">
    <?php foreach ($perms as $p): ?>
      <div class="col-md-3"><label><input type="checkbox" name="permission_ids[]" value="<?= (int)$p['id'] ?>" <?= in_array((int)$p['id'], $map[$role['id']] ?? [], true)?'checked':'' ?>> <?= e($p['slug']) ?></label></div>
    <?php endforeach; ?>
    </div>
    <button class="btn btn-primary mt-2">حفظ</button>
  </form>
</div>
<?php endforeach; ?>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/categories/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>الفئات</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2"><div class="col-md-4"><input class="form-control" name="name" placeholder="الاسم" required></div>
  <div class="col-md-4"><input class="form-control" type="number" name="sort_order" placeholder="ترتيب"></div>
  <div class="col-md-4"><button class="btn btn-primary w-100">إضافة</button></div></div>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>Slug</th><th></th></tr></thead><tbody>
<?php foreach ($categories as $c): ?>
<tr><td><?= (int)$c['id'] ?></td><td><?= e($c['name']) ?></td><td><?= e($c['slug']) ?></td>
<td><form method="post" action="/admin/categories/<?= (int)$c['id'] ?>/delete"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/payment_methods/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>طرق الدفع</h2>
<form method="post" class="card p-3 mb-3">
  <input type="hidden" name="_csrf" value="<?= csrf_token() ?>">
  <div class="row g-2">
    <div class="col-md-2"><input class="form-control" name="name" placeholder="Name" required></div>
    <div class="col-md-2"><input class="form-control" name="account_number" placeholder="رقم الحساب"></div>
    <div class="col-md-2"><input class="form-control" name="account_name" placeholder="اسم الحساب"></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="min_amount" placeholder="Min"></div>
    <div class="col-md-2"><input class="form-control" type="number" step="0.01" name="max_amount" placeholder="Max"></div>
  </div>
  <button class="btn btn-primary mt-2">إضافة</button>
</form>
<table class="table table-dark"><thead><tr><th>#</th><th>الاسم</th><th>الحساب</th><th>Min</th><th>Max</th><th></th></tr></thead><tbody>
<?php foreach ($methods as $m): ?>
<tr><td><?= (int)$m['id'] ?></td><td><?= e($m['name']) ?></td><td><?= e($m['account_number'] ?? '') ?></td><td><?= e((string)$m['min_amount']) ?></td><td><?= e((string)$m['max_amount']) ?></td>
<td><form method="post" action="/admin/payment-methods/<?= (int)$m['id'] ?>/delete"><input type="hidden" name="_csrf" value="<?= csrf_token() ?>"><button class="btn btn-sm btn-outline-danger">حذف</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

w('admin/views/wallet/index.php', <<<'PHP'
<?php ob_start(); ?>
<h2>المعاملات المالية</h2>
<table class="table table-dark"><thead><tr><th>#</th><th>المستخدم</th><th>النوع</th><th>المبلغ</th><th>قبل</th><th>بعد</th><th>التاريخ</th></tr></thead><tbody>
<?php foreach ($tx as $t): ?>
<tr><td><?= (int)$t['id'] ?></td><td><?= e($t['user_name']) ?></td><td><?= e($t['type']) ?></td><td><?= number_format((float)$t['amount'],2) ?></td><td><?= number_format((float)$t['balance_before'],2) ?></td><td><?= number_format((float)$t['balance_after'],2) ?></td><td><?= e($t['created_at']) ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php $content = ob_get_clean(); require __DIR__.'/../layout.php'; PHP);

// =========================================================
// 10) ASSETS
// =========================================================
w('public/assets/css/app.css', <<<'CSS'
body{background:var(--bg,#0B0D0F);color:#eaeaea;font-family:system-ui,"Segoe UI",Tahoma,sans-serif}
a{color:var(--primary,#BEEE11)}
.twc-nav{background:rgba(0,0,0,.35);backdrop-filter:blur(8px);border-bottom:1px solid #23272e}
.navbar-brand,.nav-link{color:#eaeaea!important}
.nav-link:hover{color:var(--primary,#BEEE11)!important}
.game-card,.product-card{background:var(--card,#181C20);border:1px solid #23272e;color:#eaeaea;transition:.2s}
.game-card:hover,.product-card:hover{transform:translateY(-4px);border-color:var(--primary,#BEEE11)}
.price{color:var(--primary,#BEEE11);font-weight:700}
.btn-primary{background:var(--primary,#BEEE11);border-color:var(--primary,#BEEE11);color:#0B0D0F;font-weight:700}
.card{background:var(--card,#181C20);color:#eaeaea;border:1px solid #23272e;border-radius:14px}
.form-control,.form-select{background:#0f1216;color:#eaeaea;border:1px solid #2a2f35}
.form-control:focus{background:#0f1216;color:#eaeaea;border-color:var(--primary,#BEEE11);box-shadow:none}
.twc-footer{background:#0d1013;border-top:1px solid #23272e;color:#8a93a3}
.alert-success{background:rgba(67,160,71,.15);color:#b6ffbb;border-color:#2e6b31}
.alert-danger{background:rgba(229,57,53,.15);color:#ffbdbd;border-color:#6b2e2e}
CSS);

w('public/assets/js/app.js', <<<'JS'
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('.add-to-cart');
  if (!btn) return;
  e.preventDefault();
  const id = btn.dataset.id;
  const csrf = document.querySelector('meta[name="csrf"]')?.content || '';
  const form = new FormData();
  form.append('product_id', id); form.append('quantity', 1); form.append('_csrf', csrf);
  const res = await fetch('/cart/add', { method:'POST', body: form, credentials:'same-origin' });
  const data = await res.json().catch(()=>({ok:false}));
  if (data.ok) { btn.textContent='✓ تمت الإضافة'; btn.classList.add('disabled'); setTimeout(()=>{btn.textContent='أضف للسلة';btn.classList.remove('disabled');},1200); }
  else { location.href = '/login'; }
});
JS);

// placeholders dirs
w('public/uploads/.gitkeep', '');
w('public/images/.gitkeep', '');

// =========================================================
// 11) LANG
// =========================================================
w('lang/ar.php', "<?php\nreturn ['home'=>'الرئيسية','games'=>'الألعاب','cart'=>'السلة','wallet'=>'المحفظة','orders'=>'الطلبات','support'=>'الدعم'];\n");
w('lang/en.php', "<?php\nreturn ['home'=>'Home','games'=>'Games','cart'=>'Cart','wallet'=>'Wallet','orders'=>'Orders','support'=>'Support'];\n");

// =========================================================
// 12) DATABASE
// =========================================================
w('database/schema.sql', <<<'SQL'
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE IF NOT EXISTS roles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  slug VARCHAR(80) NOT NULL UNIQUE,
  is_super TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permissions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(120) NOT NULL UNIQUE,
  `group` VARCHAR(60) NOT NULL,
  name VARCHAR(120) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admins (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(190) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role_id BIGINT UNSIGNED NOT NULL,
  status ENUM('active','disabled') DEFAULT 'active',
  last_login_at DATETIME NULL,
  last_login_ip VARCHAR(45) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(190) NOT NULL UNIQUE,
  phone VARCHAR(30) NULL,
  password VARCHAR(255) NOT NULL,
  avatar VARCHAR(255) NULL,
  status ENUM('active','disabled') DEFAULT 'active',
  last_login_at DATETIME NULL,
  last_login_ip VARCHAR(45) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS password_resets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY email_idx (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS categories (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  slug VARCHAR(140) NOT NULL UNIQUE,
  icon VARCHAR(255) NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  sort_order INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS games (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  category_id BIGINT UNSIGNED NULL,
  name VARCHAR(160) NOT NULL,
  slug VARCHAR(180) NOT NULL UNIQUE,
  description TEXT NULL,
  image VARCHAR(255) NULL,
  banner VARCHAR(255) NULL,
  icon VARCHAR(255) NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  featured TINYINT(1) NOT NULL DEFAULT 0,
  sort_order INT NOT NULL DEFAULT 0,
  seo_title VARCHAR(200) NULL,
  seo_description VARCHAR(300) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS products (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  game_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(180) NOT NULL,
  slug VARCHAR(200) NOT NULL UNIQUE,
  description TEXT NULL,
  image VARCHAR(255) NULL,
  price DECIMAL(12,2) NOT NULL DEFAULT 0,
  old_price DECIMAL(12,2) NULL,
  cost_price DECIMAL(12,2) NULL,
  discount DECIMAL(12,2) NOT NULL DEFAULT 0,
  sku VARCHAR(80) NULL,
  stock INT NOT NULL DEFAULT -1,
  status TINYINT(1) NOT NULL DEFAULT 1,
  featured TINYINT(1) NOT NULL DEFAULT 0,
  sort_order INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_fields (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  product_id BIGINT UNSIGNED NOT NULL,
  field_name VARCHAR(80) NOT NULL,
  field_label VARCHAR(160) NOT NULL,
  field_type ENUM('text','number','email','select','textarea') DEFAULT 'text',
  field_options TEXT NULL,
  placeholder VARCHAR(200) NULL,
  required TINYINT(1) DEFAULT 1,
  sort_order INT DEFAULT 0,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS wallets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL UNIQUE,
  balance DECIMAL(14,2) NOT NULL DEFAULT 0,
  total_deposited DECIMAL(14,2) NOT NULL DEFAULT 0,
  total_spent DECIMAL(14,2) NOT NULL DEFAULT 0,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  type ENUM('deposit','purchase','refund','admin_credit','admin_debit') NOT NULL,
  amount DECIMAL(14,2) NOT NULL,
  balance_before DECIMAL(14,2) NOT NULL,
  balance_after DECIMAL(14,2) NOT NULL,
  reference VARCHAR(120) NULL,
  description VARCHAR(300) NULL,
  admin_id BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY user_idx (user_id), KEY type_idx (type),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS payment_methods (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  description VARCHAR(300) NULL,
  icon VARCHAR(255) NULL,
  account_number VARCHAR(120) NULL,
  account_name VARCHAR(160) NULL,
  instructions TEXT NULL,
  min_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
  max_amount DECIMAL(12,2) NOT NULL DEFAULT 100000,
  status TINYINT(1) NOT NULL DEFAULT 1,
  sort_order INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS deposits (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  payment_method_id BIGINT UNSIGNED NOT NULL,
  amount DECIMAL(14,2) NOT NULL,
  sender_number VARCHAR(60) NULL,
  transaction_id VARCHAR(120) NULL,
  screenshot VARCHAR(255) NULL,
  status ENUM('pending','approved','rejected') DEFAULT 'pending',
  admin_note VARCHAR(300) NULL,
  processed_by BIGINT UNSIGNED NULL,
  processed_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY user_idx (user_id), KEY status_idx (status),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (payment_method_id) REFERENCES payment_methods(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orders (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  order_number VARCHAR(40) NOT NULL UNIQUE,
  user_id BIGINT UNSIGNED NOT NULL,
  game_id BIGINT UNSIGNED NULL,
  product_id BIGINT UNSIGNED NULL,
  quantity INT NOT NULL DEFAULT 1,
  price DECIMAL(14,2) NOT NULL,
  discount DECIMAL(14,2) NOT NULL DEFAULT 0,
  coupon_id BIGINT UNSIGNED NULL,
  final_price DECIMAL(14,2) NOT NULL,
  payment_method ENUM('wallet','manual') DEFAULT 'wallet',
  customer_data JSON NULL,
  status ENUM('pending','processing','completed','cancelled','rejected','refunded') DEFAULT 'pending',
  admin_notes TEXT NULL,
  refunded_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  KEY user_idx (user_id), KEY status_idx (status),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS order_status_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  order_id BIGINT UNSIGNED NOT NULL,
  status VARCHAR(40) NOT NULL,
  note VARCHAR(300) NULL,
  admin_id BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS coupons (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(60) NOT NULL UNIQUE,
  type ENUM('percentage','fixed') DEFAULT 'percentage',
  value DECIMAL(12,2) NOT NULL,
  min_order DECIMAL(12,2) NOT NULL DEFAULT 0,
  max_discount DECIMAL(12,2) NULL,
  starts_at DATETIME NULL,
  ends_at DATETIME NULL,
  usage_limit INT NULL,
  user_usage_limit INT NOT NULL DEFAULT 1,
  used_count INT NOT NULL DEFAULT 0,
  apply_to ENUM('all','game','product') DEFAULT 'all',
  game_id BIGINT UNSIGNED NULL,
  product_id BIGINT UNSIGNED NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS coupon_usages (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  coupon_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  order_id BIGINT UNSIGNED NOT NULL,
  discount_amount DECIMAL(12,2) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coupon_id) REFERENCES coupons(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS offers (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  description TEXT NULL,
  type ENUM('flash','game','product') DEFAULT 'flash',
  discount DECIMAL(12,2) NOT NULL DEFAULT 0,
  game_id BIGINT UNSIGNED NULL,
  product_id BIGINT UNSIGNED NULL,
  starts_at DATETIME NULL,
  ends_at DATETIME NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tickets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  subject VARCHAR(200) NOT NULL,
  category VARCHAR(60) NULL,
  priority ENUM('low','medium','high') DEFAULT 'medium',
  status ENUM('open','pending','answered','closed') DEFAULT 'open',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ticket_messages (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ticket_id BIGINT UNSIGNED NOT NULL,
  sender_type ENUM('user','admin') NOT NULL,
  sender_id BIGINT UNSIGNED NOT NULL,
  message TEXT NOT NULL,
  attachment VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NULL,
  is_admin TINYINT(1) NOT NULL DEFAULT 0,
  type VARCHAR(60) NOT NULL,
  title VARCHAR(200) NOT NULL,
  message TEXT NULL,
  url VARCHAR(255) NULL,
  is_read TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY user_read (user_id, is_read)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS banners (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  description VARCHAR(300) NULL,
  image VARCHAR(255) NOT NULL,
  button_text VARCHAR(80) NULL,
  button_url VARCHAR(255) NULL,
  starts_at DATETIME NULL,
  ends_at DATETIME NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  sort_order INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pages (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  slug VARCHAR(200) NOT NULL UNIQUE,
  content LONGTEXT NULL,
  meta_title VARCHAR(200) NULL,
  meta_description VARCHAR(300) NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS faqs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  question VARCHAR(300) NOT NULL,
  answer TEXT NOT NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  sort_order INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS testimonials (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  message TEXT NOT NULL,
  avatar VARCHAR(255) NULL,
  rating TINYINT NOT NULL DEFAULT 5,
  status TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS social_links (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  icon VARCHAR(120) NULL,
  url VARCHAR(255) NOT NULL,
  status TINYINT(1) NOT NULL DEFAULT 1,
  sort_order INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `key` VARCHAR(120) NOT NULL UNIQUE,
  `value` LONGTEXT NULL,
  `group` VARCHAR(60) NOT NULL DEFAULT 'general'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_logs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  admin_id BIGINT UNSIGNED NULL,
  action VARCHAR(120) NOT NULL,
  target_type VARCHAR(60) NULL,
  target_id BIGINT UNSIGNED NULL,
  description VARCHAR(400) NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(300) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_type ENUM('user','admin') DEFAULT 'user',
  success TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS=1;
SQL);

w('database/seed.sql', <<<'SQL'
SET NAMES utf8mb4;
INSERT IGNORE INTO categories (id,name,slug,status,sort_order) VALUES
 (1,'Mobile Games','mobile-games',1,1),(2,'PC Games','pc-games',1,2);

INSERT IGNORE INTO games (id,category_id,name,slug,description,status,featured,sort_order) VALUES
 (1,1,'PUBG Mobile','pubg-mobile','شحن شدات ببجي موبايل',1,1,1),
 (2,1,'Free Fire','free-fire','شحن جواهر فري فاير',1,1,2),
 (3,1,'Genshin Impact','genshin-impact','شحن جينشين إمباكت',1,1,3);

INSERT IGNORE INTO products (id,game_id,name,slug,price,status,featured,sort_order) VALUES
 (1,1,'60 UC','pubg-60-uc',50,1,1,1),
 (2,1,'325 UC','pubg-325-uc',240,1,1,2),
 (3,1,'660 UC','pubg-660-uc',470,1,1,3),
 (4,2,'100 Diamonds','ff-100-diamonds',60,1,1,1),
 (5,2,'310 Diamonds','ff-310-diamonds',170,1,1,2),
 (6,3,'60 Genesis Crystals','gi-60-genesis',40,1,1,1);

INSERT IGNORE INTO product_fields (product_id,field_name,field_label,field_type,placeholder,required,sort_order) VALUES
 (1,'player_id','Player ID','text','ادخل الـ Player ID',1,0),
 (2,'player_id','Player ID','text','ادخل الـ Player ID',1,0),
 (3,'player_id','Player ID','text','ادخل الـ Player ID',1,0),
 (4,'player_id','Player ID','text','ادخل الـ Player ID',1,0),
 (5,'player_id','Player ID','text','ادخل الـ Player ID',1,0),
 (6,'uid','UID','text','ادخل الـ UID',1,0);

INSERT IGNORE INTO faqs (question,answer,status,sort_order) VALUES
 ('كيف أشحن رصيد المحفظة؟','اختر طريقة دفع وارفع صورة الإيصال، سيتم المراجعة خلال دقائق.',1,1),
 ('كم تستغرق عملية شحن اللعبة؟','عادة بين 5 دقائق و30 دقيقة.',1,2);

INSERT IGNORE INTO testimonials (name,message,rating,status) VALUES
 ('أحمد','خدمة سريعة ومنظمة.',5,1),('سارة','أسعار ممتازة ودعم محترم.',5,1);

INSERT IGNORE INTO pages (title,slug,content,status) VALUES
 ('Terms of Service','terms','<p>الشروط والأحكام...</p>',1),
 ('Privacy Policy','privacy','<p>سياسة الخصوصية...</p>',1),
 ('About Us','about','<p>من نحن...</p>',1);

INSERT IGNORE INTO social_links (name,icon,url,status,sort_order) VALUES
 ('Facebook','facebook','https://facebook.com',1,1),
 ('Instagram','instagram','https://instagram.com',1,2),
 ('Discord','discord','https://discord.com',1,3);

INSERT IGNORE INTO payment_methods (name,description,min_amount,max_amount,status,sort_order) VALUES
 ('Vodafone Cash','فودافون كاش',50,10000,1,1),
 ('Orange Cash','أورنج كاش',50,10000,1,2),
 ('Etisalat Cash','اتصالات كاش',50,10000,1,3),
 ('InstaPay','انستاباي',50,20000,1,4);
SQL);

// =========================================================
// 13) INSTALLER
// =========================================================
w('install/index.php', <<<'PHP'
<?php
declare(strict_types=1);
$lock = __DIR__ . '/install.lock';
if (file_exists($lock)) { http_response_code(403); exit('Installer disabled. Delete install.lock to re-enable.'); }
session_start();
$step = (int)($_GET['step'] ?? 1);
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['test_db'])) {
        try {
            $dsn = "mysql:host={$_POST['db_host']};dbname={$_POST['db_name']};charset=utf8mb4";
            $pdo = new PDO($dsn, $_POST['db_user'], $_POST['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $_SESSION['db'] = ['host'=>$_POST['db_host'],'name'=>$_POST['db_name'],'user'=>$_POST['db_user'],'pass'=>$_POST['db_pass']];
            header('Location: index.php?step=2'); exit;
        } catch (Throwable $e) { $errors[] = 'DB error: ' . $e->getMessage(); }
    }
    if (isset($_POST['create_admin'])) {
        try {
            $db = $_SESSION['db'] ?? throw new RuntimeException('DB config missing');
            $dsn = "mysql:host={$db['host']};dbname={$db['name']};charset=utf8mb4";
            $pdo = new PDO($dsn, $db['user'], $db['pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $schema = file_get_contents(__DIR__ . '/../database/schema.sql');
            $pdo->exec($schema);
            $pdo->exec("INSERT IGNORE INTO roles (id,name,slug,is_super) VALUES
                (1,'Super Admin','super_admin',1),(2,'Admin','admin',0),(3,'Manager','manager',0),
                (4,'Support','support',0),(5,'Accountant','accountant',0),(6,'Product Manager','product_manager',0)");
            $perms = [
                ['users.view','users','View Users'],['users.create','users','Create Users'],['users.edit','users','Edit Users'],['users.delete','users','Delete Users'],
                ['games.view','games','View Games'],['games.create','games','Create Games'],['games.edit','games','Edit Games'],['games.delete','games','Delete Games'],
                ['products.view','products','View Products'],['products.create','products','Create Products'],['products.edit','products','Edit Products'],['products.delete','products','Delete Products'],
                ['orders.view','orders','View Orders'],['orders.edit','orders','Edit Orders'],
                ['wallet.view','wallet','View Wallet'],['wallet.manage','wallet','Manage Wallet'],
                ['deposits.view','deposits','View Deposits'],['deposits.approve','deposits','Approve Deposits'],['deposits.reject','deposits','Reject Deposits'],
                ['coupons.view','coupons','View Coupons'],['coupons.manage','coupons','Manage Coupons'],
                ['offers.view','offers','View Offers'],['offers.manage','offers','Manage Offers'],
                ['tickets.view','tickets','View Tickets'],['tickets.reply','tickets','Reply Tickets'],
                ['content.manage','content','Manage Content'],
                ['settings.view','settings','View Settings'],['settings.edit','settings','Edit Settings'],
                ['admins.view','admins','View Admins'],['admins.manage','admins','Manage Admins'],
                ['roles.manage','roles','Manage Roles'],['logs.view','logs','View Logs'],
            ];
            $ins = $pdo->prepare("INSERT IGNORE INTO permissions (slug,`group`,name) VALUES (?,?,?)");
            foreach ($perms as $p) $ins->execute($p);
            $hash = password_hash($_POST['admin_password'], PASSWORD_BCRYPT, ['cost'=>12]);
            $pdo->prepare("INSERT INTO admins (name,email,password,role_id,status) VALUES (?,?,?,1,'active')")
                ->execute([$_POST['admin_name'], $_POST['admin_email'], $hash]);
            $defaults = [
                ['site_name','The Witcher Store','general'],
                ['site_description','متجر شحن الألعاب الأول','general'],
                ['currency','EGP','general'],
                ['order_prefix','TWC','orders'],
                ['maintenance_mode','0','maintenance'],
                ['enable_store','1','store'],
                ['enable_registration','1','store'],
                ['enable_wallet','1','store'],
                ['min_deposit','10','store'],
                ['max_deposit','10000','store'],
                ['primary_color','#BEEE11','appearance'],
                ['secondary_color','#B2FF59','appearance'],
                ['background_color','#0B0D0F','appearance'],
            ];
            $s = $pdo->prepare("INSERT IGNORE INTO settings (`key`,`value`,`group`) VALUES (?,?,?)");
            foreach ($defaults as $d) $s->execute($d);
            $seed = file_get_contents(__DIR__ . '/../database/seed.sql');
            if ($seed) $pdo->exec($seed);
            $cfg = "<?php\nreturn [\n    'host' => ".var_export($db['host'],true).",\n    'name' => ".var_export($db['name'],true).",\n    'user' => ".var_export($db['user'],true).",\n    'pass' => ".var_export($db['pass'],true).",\n    'charset' => 'utf8mb4',\n];\n";
            file_put_contents(__DIR__ . '/../config/database.php', $cfg);
            file_put_contents($lock, date('c'));
            header('Location: index.php?step=3'); exit;
        } catch (Throwable $e) { $errors[] = $e->getMessage(); }
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"><title>Install · The Witcher Store</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
<style>body{background:#0B0D0F;color:#eee}.card{background:#181C20;border:1px solid #2a2f35}.btn-primary{background:#BEEE11;border-color:#BEEE11;color:#0B0D0F;font-weight:700}</style>
</head>
<body class="py-5">
<div class="container" style="max-width:720px">
<h1 class="mb-4 text-center" style="color:#BEEE11">The Witcher Store · Installer</h1>
<?php foreach ($errors as $e): ?><div class="alert alert-danger"><?=htmlspecialchars($e)?></div><?php endforeach; ?>
<?php if ($step === 1): ?>
  <div class="card p-4"><h3>Step 1 · Database</h3>
    <form method="post">
      <div class="mb-3"><label>DB Host</label><input class="form-control" name="db_host" value="localhost" required></div>
      <div class="mb-3"><label>DB Name</label><input class="form-control" name="db_name" required></div>
      <div class="mb-3"><label>DB User</label><input class="form-control" name="db_user" required></div>
      <div class="mb-3"><label>DB Password</label><input class="form-control" type="password" name="db_pass"></div>
      <button class="btn btn-primary" name="test_db" value="1">Test & Continue</button>
    </form>
  </div>
<?php elseif ($step === 2): ?>
  <div class="card p-4"><h3>Step 2 · Admin Account</h3>
    <form method="post">
      <div class="mb-3"><label>Admin Name</label><input class="form-control" name="admin_name" required></div>
      <div class="mb-3"><label>Admin Email</label><input class="form-control" type="email" name="admin_email" required></div>
      <div class="mb-3"><label>Admin Password</label><input class="form-control" type="password" name="admin_password" required></div>
      <button class="btn btn-primary" name="create_admin" value="1">Install</button>
    </form>
  </div>
<?php else: ?>
  <div class="card p-4 text-center"><h3>✅ Installation Complete</h3>
    <a href="/" class="btn btn-primary">Go to Site</a>
    <a href="/admin" class="btn btn-outline-light ms-2">Admin</a>
  </div>
<?php endif; ?>
</div></body></html>
PHP);

// =========================================================
// 14) CRON
// =========================================================
w('cron/expire_offers.php', "<?php\nrequire __DIR__.'/../app/helpers/functions.php';\nrequire __DIR__.'/../app/helpers/security.php';\ndb()->exec(\"UPDATE offers SET status=0 WHERE ends_at IS NOT NULL AND ends_at < NOW() AND status=1\");\necho 'OK\\n';\n");
w('cron/expire_coupons.php', "<?php\nrequire __DIR__.'/../app/helpers/functions.php';\nrequire __DIR__.'/../app/helpers/security.php';\ndb()->exec(\"UPDATE coupons SET status=0 WHERE ends_at IS NOT NULL AND ends_at < NOW() AND status=1\");\necho 'OK\\n';\n");
w('cron/cleanup_sessions.php', "<?php\necho 'OK\\n';\n");

// =========================================================
// 15) README
// =========================================================
w('README.md', <<<'MD'
# The Witcher Store

Full PHP 8 + MySQL game top-up platform.

## Requirements
- PHP 8.2+ (PDO MySQL, mbstring, fileinfo, json)
- MySQL 5.7+ / MariaDB 10.3+
- Apache with mod_rewrite

## Installation
1. Upload project to cPanel `public_html`.
2. Create MySQL database + user in cPanel.
3. Open `https://yourdomain.com/install`.
4. Fill DB credentials → click Test.
5. Fill admin account → click Install.
6. `/install` gets locked after success.
7. Login at `/admin/login` with your admin account.

## Folder Structure
- `app/` — controllers, models, services, helpers, views
- `admin/` — admin panel
- `config/` — configuration
- `public/` — web root (assets, uploads)
- `routes/` — route definitions
- `database/` — schema.sql, seed.sql
- `install/` — installer wizard
- `cron/` — cron jobs
- `lang/` — translations

## Cron Jobs (cPanel)
