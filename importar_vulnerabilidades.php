<?php
require_once 'config.php';

function extractVulnerabilityData($item) {
    $data = [];
    
    // Si es un documento CSAF de Red Hat
    if (isset($item['document'])) {
        $doc = $item['document'];
        
        // Extraer CVE ID de las referencias o del texto de las notas
        if (isset($doc['references'])) {
            foreach ($doc['references'] as $ref) {
                if (isset($ref['url']) && preg_match('/CVE-\d{4}-\d+/', $ref['url'], $matches)) {
                    $data['cve'] = $matches[0];
                    break;
                }
            }
        }
        
        // Si no encontramos el CVE en las referencias, buscarlo en las notas
        if (empty($data['cve']) && isset($doc['notes'])) {
            foreach ($doc['notes'] as $note) {
                if (preg_match('/CVE-\d{4}-\d+/', $note['text'], $matches)) {
                    $data['cve'] = $matches[0];
                    break;
                }
            }
        }
        
        // Si no hay CVE, usar el ID de tracking como identificador
        if (empty($data['cve']) && isset($doc['tracking']['id'])) {
            $data['cve'] = 'RHSA-' . $doc['tracking']['id'];
        }
        
        // Extraer nombre/título
        if (isset($doc['title'])) {
            $data['nombre'] = $doc['title'];
        }
        
        // Extraer sistema
        if (isset($doc['product_tree']['branches'])) {
            foreach ($doc['product_tree']['branches'] as $branch) {
                if (isset($branch['branches'])) {
                    foreach ($branch['branches'] as $subBranch) {
                        if (isset($subBranch['branches'])) {
                            foreach ($subBranch['branches'] as $productBranch) {
                                if (isset($productBranch['product']['name'])) {
                                    $data['sistema'] = $productBranch['product']['name'];
                                    break 3;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Si no encontramos el sistema en el árbol de productos, intentar extraerlo del título o notas
        if (empty($data['sistema'])) {
            if (isset($doc['title'])) {
                if (preg_match('/update for (.*?) is now available/', $doc['title'], $matches)) {
                    $data['sistema'] = $matches[1];
                } elseif (preg_match('/Updated (.*?) container image/', $doc['title'], $matches)) {
                    $data['sistema'] = $matches[1];
                }
            }
            
            // Si aún no tenemos sistema, buscar en las notas
            if (empty($data['sistema']) && isset($doc['notes'])) {
                foreach ($doc['notes'] as $note) {
                    if (isset($note['text'])) {
                        if (preg_match('/Red Hat (.*?) Storage/', $note['text'], $matches)) {
                            $data['sistema'] = $matches[1];
                            break;
                        }
                    }
                }
            }
        }
        
        // Extraer descripción
        if (isset($doc['notes'])) {
            foreach ($doc['notes'] as $note) {
                if ($note['category'] === 'summary' || $note['category'] === 'general') {
                    $data['descripcion'] = $note['text'];
                    break;
                }
            }
        }
        
        // Extraer fechas
        if (isset($doc['tracking']['initial_release_date'])) {
            $data['fecha_descubrimiento'] = date('Y-m-d', strtotime($doc['tracking']['initial_release_date']));
        }
        if (isset($doc['tracking']['current_release_date'])) {
            $data['fecha_lanzamiento'] = date('Y-m-d', strtotime($doc['tracking']['current_release_date']));
        }
        
        // Extraer gravedad
        if (isset($doc['aggregate_severity']['text'])) {
            $data['gravedad_cvss'] = $doc['aggregate_severity']['text'];
        }
    }
    // Si es un registro CVE normal
    else {
        // Extraer CVE ID
        if (isset($item['cveMetadata']['cveId'])) {
            $data['cve'] = $item['cveMetadata']['cveId'];
        } elseif (isset($item['id']) && strpos($item['id'], 'CVE-') === 0) {
            $data['cve'] = $item['id'];
        } elseif (isset($item['aliases']) && !empty($item['aliases'])) {
            foreach ($item['aliases'] as $alias) {
                if (strpos($alias, 'CVE-') === 0) {
                    $data['cve'] = $alias;
                    break;
                }
            }
        }

        // Extraer nombre/título
        if (isset($item['summary'])) {
            $data['nombre'] = $item['summary'];
        } elseif (isset($item['containers']['cna']['descriptions'][0]['value'])) {
            $data['nombre'] = substr($item['containers']['cna']['descriptions'][0]['value'], 0, 255);
        }

        // Extraer sistema
        if (isset($item['affected'][0]['package']['name'])) {
            $data['sistema'] = $item['affected'][0]['package']['name'];
        } elseif (isset($item['containers']['cna']['affected'][0]['product'])) {
            $data['sistema'] = $item['containers']['cna']['affected'][0]['product'];
        }

        // Extraer descripción
        if (isset($item['details'])) {
            $data['descripcion'] = $item['details'];
        } elseif (isset($item['containers']['cna']['descriptions'][0]['value'])) {
            $data['descripcion'] = $item['containers']['cna']['descriptions'][0]['value'];
        }

        // Extraer fechas
        if (isset($item['cveMetadata']['datePublished'])) {
            $data['fecha_descubrimiento'] = date('Y-m-d', strtotime($item['cveMetadata']['datePublished']));
        } elseif (isset($item['published'])) {
            $data['fecha_descubrimiento'] = date('Y-m-d', strtotime($item['published']));
        }

        if (isset($item['cveMetadata']['dateUpdated'])) {
            $data['fecha_lanzamiento'] = date('Y-m-d', strtotime($item['cveMetadata']['dateUpdated']));
        } elseif (isset($item['modified'])) {
            $data['fecha_lanzamiento'] = date('Y-m-d', strtotime($item['modified']));
        }

        // Extraer gravedad CVSS
        if (isset($item['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'])) {
            $data['gravedad_cvss'] = $item['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'];
        } elseif (isset($item['database_specific']['severity'])) {
            $data['gravedad_cvss'] = $item['database_specific']['severity'];
        } elseif (isset($item['severity'][0]['score'])) {
            $data['gravedad_cvss'] = $item['severity'][0]['score'];
        }
    }

    return $data;
}

try {
    $conn = getDBConnection();
    
    // Obtener datos desde la API
    $response = @file_get_contents(API_URL);
    if ($response === false) {
        throw new Exception("No se pudo conectar con la API");
    }
    
    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Error al decodificar la respuesta de la API: " . json_last_error_msg());
    }
    
    if (!$data) {
        throw new Exception("No se recibieron datos de la API");
    }
    
    $imported = 0;
    $updated = 0;
    $skipped = 0;
    $errors = 0;
    $error_log = [];
    
    // Preparar las consultas SQL
    $checkStmt = $conn->prepare("SELECT id FROM vulnerabilidades WHERE cve = ?");
    $insertStmt = $conn->prepare("INSERT INTO vulnerabilidades (cve, nombre, id_interno, sistema, descripcion, fecha_descubrimiento, fecha_lanzamiento, gravedad_cvss) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $updateStmt = $conn->prepare("UPDATE vulnerabilidades SET nombre = ?, sistema = ?, descripcion = ?, fecha_descubrimiento = ?, fecha_lanzamiento = ?, gravedad_cvss = ? WHERE cve = ?");
    
    if (!$checkStmt || !$insertStmt || !$updateStmt) {
        throw new Exception("Error al preparar las consultas: " . $conn->error);
    }
    
    foreach ($data as $item) {
        try {
            $vulnData = extractVulnerabilityData($item);
            
            // Validar datos requeridos
            if (empty($vulnData['cve']) || empty($vulnData['nombre'])) {
                $errors++;
                $error_log[] = "Datos incompletos para: " . json_encode($item);
                continue;
            }
            
            // Verificar si el CVE ya existe
            $checkStmt->bind_param("s", $vulnData['cve']);
            $checkStmt->execute();
            $result = $checkStmt->get_result();
            
            // Preparar los valores
            $cve = $vulnData['cve'];
            $nombre = $vulnData['nombre'];
            $id_interno = '';
            $sistema = $vulnData['sistema'] ?? '';
            $descripcion = $vulnData['descripcion'] ?? '';
            $fecha_descubrimiento = $vulnData['fecha_descubrimiento'] ?? null;
            $fecha_lanzamiento = $vulnData['fecha_lanzamiento'] ?? null;
            $gravedad_cvss = $vulnData['gravedad_cvss'] ?? 'N/A';
            
            if ($result->num_rows > 0) {
                // Actualizar registro existente
                $updateStmt->bind_param("sssssss", 
                    $nombre,
                    $sistema,
                    $descripcion,
                    $fecha_descubrimiento,
                    $fecha_lanzamiento,
                    $gravedad_cvss,
                    $cve
                );
                
                if ($updateStmt->execute()) {
                    $updated++;
                } else {
                    $errors++;
                    $error_log[] = "Error al actualizar CVE {$cve}: " . $updateStmt->error;
                }
            } else {
                // Insertar nuevo registro
                $insertStmt->bind_param("ssssssss", 
                    $cve,
                    $nombre,
                    $id_interno,
                    $sistema,
                    $descripcion,
                    $fecha_descubrimiento,
                    $fecha_lanzamiento,
                    $gravedad_cvss
                );
                
                if ($insertStmt->execute()) {
                    $imported++;
                } else {
                    $errors++;
                    $error_log[] = "Error al insertar CVE {$cve}: " . $insertStmt->error;
                }
            }
        } catch (Exception $e) {
            $errors++;
            $error_log[] = "Error procesando vulnerabilidad: " . $e->getMessage();
        }
    }
    
    $checkStmt->close();
    $insertStmt->close();
    $updateStmt->close();
    $conn->close();
    
    echo json_encode([
        'success' => true,
        'message' => "Importación completada. Nuevos: $imported, Actualizados: $updated, Errores: $errors",
        'error_log' => $error_log
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => "Error: " . $e->getMessage()
    ], JSON_PRETTY_PRINT);
}
?> 