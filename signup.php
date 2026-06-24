<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

require_once "Connection.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit();
}

try {
    $datos = json_decode(file_get_contents("php://input"), true);

    // --- Validate required fields ---
    if (empty($datos["username"]) || empty($datos["email"]) || empty($datos["password"])) {
        http_response_code(400);
        echo json_encode(["error" => "Fields username, email and password are required"]);
        exit();
    }

    $username = trim($datos["username"]);
    $email    = trim($datos["email"]);
    $password = $datos["password"];

    // --- Validate email ---
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(["error" => "Email address format is not valid"]);
        exit();
    }

    // --- Validate password ---
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

    // --- Read credentials from config.ini ---
    $config = parse_ini_file("config.ini", true);

    if ($config === false) {
        throw new RuntimeException("Could not read config.ini file");
    }

    // --- Database connection ---
    $mysqli = new mysqli(
        $config["database"]["host"],
        $config["database"]["username"],
        $config["database"]["password"],
        $config["database"]["dbname"]
    );

    if ($mysqli->connect_error) {
        throw new RuntimeException("Connection error: " . $mysqli->connect_error);
    }

    $db = new Connection($mysqli);

    // --- Check if email already exists ---
    $existente = $db->executeQuery(
        "SELECT id FROM usuarios WHERE email = ?",
        "s",
        [$email]
    );

    if (!empty($existente)) {
        http_response_code(409);
        echo json_encode(["error" => "Email is already registered"]);
        exit();
    }

    // --- Hash password with bcrypt ---
    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    // --- Insert user ---
    $db->executeQuery(
        "INSERT INTO usuarios (username, email, password_hash) VALUES (?, ?, ?)",
        "sss",
        [$username, $email, $password_hash]
    );

    http_response_code(201);
    echo json_encode(["message" => "User registered successfully"]);
} catch (RuntimeException $e) {
    http_response_code(500);
    echo json_encode(["error" => "Internal server error: " . $e->getMessage()]);
}
