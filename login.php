<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit();
}

header("Content-Type: application/json");

require_once "Connection.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit();
}

try {
    $datos = json_decode(file_get_contents("php://input"), true);

    // --- Validar campos presentes ---
    if (empty($datos["email"]) || empty($datos["password"])) {
        http_response_code(400);
        echo json_encode(["error" => "Please, fill all the fields"]);
        exit();
    }

    $email    = trim($datos["email"]);
    $password = $datos["password"];

    // --- Leer credenciales desde config.ini ---
    $config = parse_ini_file("config.ini", true);

    if ($config === false) {
        throw new RuntimeException("config.ini couldn't be read");
    }

    // --- Conexión a la base de datos ---
    $mysqli = new mysqli(
        $config["database"]["host"],
        $config["database"]["username"],
        $config["database"]["password"],
        $config["database"]["dbname"]
    );

    if ($mysqli->connect_error) {
        throw new RuntimeException("Conection error: " . $mysqli->connect_error);
    }

    $db = new Connection($mysqli);

    // --- Buscar usuario por correo ---
    $resultado = $db->executeQuery(
        "SELECT id, password_hash FROM usuarios WHERE email = ?",
        "s",
        [$email]
    );

    if (empty($resultado)) {
        http_response_code(401);
        echo json_encode(["error" => "incorrect credentials"]);
        exit();
    }

    $usuario = $resultado[0];

    // --- Verificar contraseña con bcrypt ---
    if (!password_verify($password, $usuario["password_hash"])) {
        http_response_code(401);
        echo json_encode(["error" => "incorrect credentials"]);
        exit();
    }

    // --- Generar token y guardarlo en la base de datos ---
    $token = bin2hex(random_bytes(32));

    $db->executeQuery(
        "UPDATE usuarios SET token = ? WHERE id = ?",
        "si",
        [$token, $usuario["id"]]
    );

    http_response_code(200);
    echo json_encode([
        "Message" => "User logged in successfuly",
        "token"   => $token
    ]);
} catch (RuntimeException $e) {
    http_response_code(500);
    echo json_encode(["error" => "internal server error: " . $e->getMessage()]);
}
