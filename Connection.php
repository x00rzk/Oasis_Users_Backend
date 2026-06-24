<?php

class Connection {
    private mysqli $conn;

    public function __construct(mysqli $conn) {
        $this->conn = $conn;
    }

    /**
     * @param string $sql    Ej: "SELECT * FROM usuarios WHERE email = ?"
     * @param string $types  Ej: "s" (string), "i" (int), "d" (double), "b" (blob)
     * @param array  $values Ej: ["correo@ejemplo.com"]
     * @return array         Filas como array asociativo, o array vacío si no hay resultados
     */
    public function executeQuery(string $sql, string $types = "", array $values = []): array {
        $stmt = $this->conn->prepare($sql);

        if (!$stmt) {
            throw new RuntimeException("Error al preparar la consulta: " . $this->conn->error);
        }

        if (!empty($types) && !empty($values)) {
            $stmt->bind_param($types, ...$values);
        }

        $stmt->execute();

        $resultado = $stmt->get_result();

        if ($resultado && $resultado->num_rows > 0) {
            return $resultado->fetch_all(MYSQLI_ASSOC);
        }

        return [];
    }
}