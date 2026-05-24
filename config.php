<?php
// Configuración de la base de datos
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ciberseguridad');

// Configuración de la aplicación
define('ITEMS_PER_PAGE', 50);
define('API_URL', 'https://cve.circl.lu/api/last');

// Función para obtener la conexión a la base de datos
function getDBConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        throw new Exception("Database connection failed");
    }
    return $conn;
}
?> 