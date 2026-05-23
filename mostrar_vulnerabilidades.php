<?php
require_once 'config.php';

try {
    $conn = getDBConnection();
    
    // Construir la consulta SQL
    $sql = "SELECT * FROM vulnerabilidades ORDER BY fecha_descubrimiento DESC";
    
    $result = $conn->query($sql);
    
    if (!$result) {
        throw new Exception("Error al ejecutar la consulta: " . $conn->error);
    }
    
    $vulnerabilidades = [];
    while ($row = $result->fetch_assoc()) {
        $vulnerabilidades[] = [
            'cve' => $row['cve'],
            'nombre' => $row['nombre'],
            'sistema' => $row['sistema'],
            'descripcion' => $row['descripcion'],
            'fecha_descubrimiento' => $row['fecha_descubrimiento'],
            'fecha_lanzamiento' => $row['fecha_lanzamiento'],
            'gravedad_cvss' => $row['gravedad_cvss']
        ];
    }
    
    $conn->close();
    
    // Devolver los datos en formato JSON
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'data' => $vulnerabilidades
    ]);
    
} catch (Exception $e) {
    header('Content-Type: application/json');
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => "Error: " . $e->getMessage()
    ]);
}
?>
