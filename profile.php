<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, PUT, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit();
}
header("Content-Type: application/json");
require_once "Connection.php";

if (!in_array($_SERVER["REQUEST_METHOD"], ["GET", "PUT"])) {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit();
}

try {
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

    // --- Obtener token desde el header Authorization: Bearer <token> ---
    $headers = function_exists("getallheaders") ? getallheaders() : [];
    $authHeader = $headers["Authorization"] ?? $headers["authorization"] ?? "";

    if (empty($authHeader) || !preg_match('/Bearer\s+(.+)/i', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(["error" => "Missing or invalid Authorization header"]);
        exit();
    }
    $token = trim($matches[1]);

    // --- Buscar usuario por token ---
    $resultado = $db->executeQuery(
        "SELECT id, username, email FROM usuarios WHERE token = ?",
        "s",
        [$token]
    );
    if (empty($resultado)) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid or expired token"]);
        exit();
    }
    $usuario = $resultado[0];

    // ==========================================================
    // GET → devolver perfil
    // ==========================================================
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        http_response_code(200);
        echo json_encode([
            "id"       => $usuario["id"],
            "username" => $usuario["username"],
            "email"    => $usuario["email"]
        ]);
        exit();
    }

    // ==========================================================
    // PUT → editar perfil
    // ==========================================================
    $datos = json_decode(file_get_contents("php://input"), true);

    if (empty($datos) || (!isset($datos["username"]) && !isset($datos["email"]) && !isset($datos["password"]))) {
        http_response_code(400);
        echo json_encode(["error" => "Provide at least one field to update: username, email or password"]);
        exit();
    }

    $campos = [];
    $tipos  = "";
    $valores = [];

    // --- Username ---
    if (isset($datos["username"]) && trim($datos["username"]) !== "") {
        $campos[]  = "username = ?";
        $tipos    .= "s";
        $valores[] = trim($datos["username"]);
    }

    // --- Email ---
    if (isset($datos["email"]) && trim($datos["email"]) !== "") {
        $email = trim($datos["email"]);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(["error" => "Email address format is not valid"]);
            exit();
        }
        // Verificar que el email no esté en uso por otro usuario
        $existente = $db->executeQuery(
            "SELECT id FROM usuarios WHERE email = ? AND id != ?",
            "si",
            [$email, $usuario["id"]]
        );
        if (!empty($existente)) {
            http_response_code(409);
            echo json_encode(["error" => "Email is already registered by another user"]);
            exit();
        }
        $campos[]  = "email = ?";
        $tipos    .= "s";
        $valores[] = $email;
    }

    // --- Password (opcional) ---
    if (isset($datos["password"]) && $datos["password"] !== "") {
        $password = $datos["password"];
        if (strlen($password) < 8) {
            http_response_code(400);
            echo json_encode(["error" => "Password must be at least 8 characters long"]);
            exit();
        }
        if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password)) {
            http_response_code(400);
            echo json_encode(["error" => "Password must contain at least one uppercase and one lowercase letter"]);
            exit();
        }
        $campos[]  = "password_hash = ?";
        $tipos    .= "s";
        $valores[] = password_hash($password, PASSWORD_BCRYPT);
    }

    if (empty($campos)) {
        http_response_code(400);
        echo json_encode(["error" => "No valid fields were provided"]);
        exit();
    }

    // --- Construir y ejecutar el UPDATE dinámico ---
    $sql = "UPDATE usuarios SET " . implode(", ", $campos) . " WHERE id = ?";
    $tipos    .= "i";
    $valores[] = $usuario["id"];

    $db->executeQuery($sql, $tipos, $valores);

    // --- Volver a leer el perfil actualizado ---
    $actualizado = $db->executeQuery(
        "SELECT id, username, email FROM usuarios WHERE id = ?",
        "i",
        [$usuario["id"]]
    )[0];

    http_response_code(200);
    echo json_encode([
        "message" => "Profile updated successfully",
        "profile" => $actualizado
    ]);
} catch (RuntimeException $e) {
    http_response_code(500);
    echo json_encode(["error" => "Internal server error: " . $e->getMessage()]);
}
