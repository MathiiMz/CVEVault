<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

require_once 'config.php';

// Manejar preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Verificar que sea una petición GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Método no permitido']);
    exit();
}

try {
    $conn = getDBConnection();
    
    // Construir la consulta base
    $query = "SELECT * FROM vulnerabilidades WHERE 1=1";
    $params = [];
    $types = "";
    
    // Filtros
    if (isset($_GET['cve'])) {
        $query .= " AND cve LIKE ?";
        $params[] = "%" . $_GET['cve'] . "%";
        $types .= "s";
    }
    
    if (isset($_GET['sistema'])) {
        $query .= " AND sistema LIKE ?";
        $params[] = "%" . $_GET['sistema'] . "%";
        $types .= "s";
    }
    
    if (isset($_GET['gravedad'])) {
        $query .= " AND gravedad_cvss = ?";
        $params[] = $_GET['gravedad'];
        $types .= "s";
    }
    
    if (isset($_GET['fecha_desde'])) {
        $query .= " AND fecha_descubrimiento >= ?";
        $params[] = $_GET['fecha_desde'];
        $types .= "s";
    }
    
    if (isset($_GET['fecha_hasta'])) {
        $query .= " AND fecha_descubrimiento <= ?";
        $params[] = $_GET['fecha_hasta'];
        $types .= "s";
    }
    
    // Ordenamiento
    $orderBy = isset($_GET['ordenar_por']) ? $_GET['ordenar_por'] : 'fecha_descubrimiento';
    $orden = isset($_GET['orden']) && strtoupper($_GET['orden']) === 'ASC' ? 'ASC' : 'DESC';
    $query .= " ORDER BY $orderBy $orden";
    
    // Paginación
    $limit = isset($_GET['limite']) ? (int)$_GET['limite'] : 50;
    $offset = isset($_GET['pagina']) ? ((int)$_GET['pagina'] - 1) * $limit : 0;
    $query .= " LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    $types .= "ii";
    
    // Preparar y ejecutar la consulta
    $stmt = $conn->prepare($query);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Obtener el total de registros para la paginación
    $countQuery = "SELECT COUNT(*) as total FROM vulnerabilidades WHERE 1=1";
    if (isset($_GET['cve'])) {
        $countQuery .= " AND cve LIKE '%" . $_GET['cve'] . "%'";
    }
    if (isset($_GET['sistema'])) {
        $countQuery .= " AND sistema LIKE '%" . $_GET['sistema'] . "%'";
    }
    if (isset($_GET['gravedad'])) {
        $countQuery .= " AND gravedad_cvss = '" . $_GET['gravedad'] . "'";
    }
    $totalResult = $conn->query($countQuery);
    $total = $totalResult->fetch_assoc()['total'];
    
    // Formatear los resultados
    $vulnerabilidades = [];
    while ($row = $result->fetch_assoc()) {
        $vulnerabilidades[] = [
            'id' => $row['id'],
            'cve' => $row['cve'],
            'nombre' => $row['nombre'],
            'sistema' => $row['sistema'],
            'descripcion' => $row['descripcion'],
            'fecha_descubrimiento' => $row['fecha_descubrimiento'],
            'fecha_lanzamiento' => $row['fecha_lanzamiento'],
            'gravedad_cvss' => $row['gravedad_cvss']
        ];
    }
    
    // Preparar la respuesta
    $response = [
        'success' => true,
        'data' => $vulnerabilidades,
        'paginacion' => [
            'total' => (int)$total,
            'pagina_actual' => $offset / $limit + 1,
            'total_paginas' => ceil($total / $limit),
            'limite' => $limit
        ]
    ];
    
    echo json_encode($response, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Error interno del servidor: ' . $e->getMessage()
    ]);
} finally {
    if (isset($stmt)) {
        $stmt->close();
    }
    if (isset($conn)) {
        $conn->close();
    }
}
?> 