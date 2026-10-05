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
            session_regenerate_id(true);
