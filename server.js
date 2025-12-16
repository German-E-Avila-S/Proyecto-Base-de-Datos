const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const upload = multer({ dest: 'uploads/' });
const PDFDocument = require("pdfkit");
const fs = require("fs");
const app = express();
require('dotenv').config();
// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      next();
    } else {
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Acceso Denegado</title>

          <!-- Bootstrap CSS -->
          <link 
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" 
            rel="stylesheet"
          >
        </head>
        <body class="bg-light d-flex justify-content-center align-items-center vh-100">

          <div class="card shadow p-4" style="max-width: 400px; width: 100%;">
            <h3 class="text-danger text-center mb-3">Acceso denegado</h3>
            <p class="text-center">No tienes permisos para acceder a esta sección.</p>

            <div class="d-grid">
              <a href="/" class="btn btn-primary">Volver al inicio</a>
            </div>
          </div>

          <!-- Bootstrap JS -->
          <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
      `;

      res.status(403).send(html);
    }
  };
}

// Ruta para la página principal
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public')));

// Configurar conexión a MySQL
const connection = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASSWORD,   // Contraseña desde .env
  database: process.env.DB_NAME,    // Nombre de la base de datos desde .env
  timezone: 'America/Tijuana'
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));


// Iniciar sesión
app.post('/login', (req, res) => {
    const { nombre_usuario, contraseña } = req.body;

    if (!nombre_usuario || !contraseña) {
        return res.status(400).send("Faltan datos");
    }

    // Consulta al usuario
    const sql = "SELECT * FROM usuarios WHERE nombre_usuario = ?";

    connection.query(sql, [nombre_usuario], async (err, rows) => {
        if (err) {
            console.error("Error en la consulta:", err);
            return res.status(500).send("Error del servidor");
        }

        // Usuario no encontrado
        if (rows.length === 0) {
            console.log("Usuario no encontrado");
            return res.redirect('/login.html');
        }

        const user = rows[0];

        try {
            // Comparar contraseña ingresada con la contraseña encriptada
            const esCorrecta = await bcrypt.compare(contraseña, user.contraseña);

            if (!esCorrecta) {
                console.log("Contraseña incorrecta");
                return res.redirect('/login.html');
            }

            // Guardar sesión
            req.session.user = {
                id: user.id,
                nombre_usuario: user.nombre_usuario,
                tipo_usuario: user.tipo_usuario
            };

            console.log("Sesión iniciada:", req.session.user);

            // Redirigir a la página principal o dashboard
            res.redirect('/');

        } catch (error) {
            console.error("Error comparando contraseñas:", error);
            res.status(500).send("Error interno");
        }
    });
});

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', (req, res) => {
    if (!req.session.user) {
        return res.json({ tipo_usuario: null });
    }

    res.json({
        tipo_usuario: req.session.user.tipo_usuario
    });
});


//Ruta para ver perfil
app.get('/mis-datos',requireLogin,(req, res) => {
    if (!req.session.user) {
        return res.redirect('/login.html'); 
    }

    const userId = req.session.user.id;

    const query = `SELECT id, nombre_usuario, tipo_usuario 
                   FROM usuarios 
                   WHERE id = ?`;

    connection.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Error al obtener datos:", err);
            return res.status(500).send("Error interno");
        }

        if (results.length === 0) {
            return res.status(404).send("Usuario no encontrado");
        }

        const usuario = results[0];

        // --- Respuesta HTML con Bootstrap ---
        res.send(`
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Mis Datos</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>

            <body class="bg-light">

                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">

                            <div class="card shadow">
                                <div class="card-header bg-primary text-white text-center">
                                    <h3>Datos del Usuario</h3>
                                </div>

                                <div class="card-body">

                                    <div class="mb-3">
                                        <label class="fw-bold">ID:</label>
                                        <p class="form-control">${usuario.id}</p>
                                    </div>

                                    <div class="mb-3">
                                        <label class="fw-bold">Usuario:</label>
                                        <p class="form-control">${usuario.nombre_usuario}</p>
                                    </div>

                                    <div class="mb-3">
                                        <label class="fw-bold">Tipo de Usuario:</label>
                                        <p class="form-control text-capitalize">${usuario.tipo_usuario}</p>
                                    </div>

                                    <div class="text-center">
                                        <a href="/" class="btn btn-secondary">Volver</a>
                                    </div>

                                </div>
                            </div>

                        </div>
                    </div>
                </div>

            </body>
            </html>
        `);
    });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Ruta protegida (Página principal después de iniciar sesión)
app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});


////USUARIOOOOOOO////
//Regitrar USUARIO
app.post('/registrar', async (req, res) => {
    const { nombre_usuario, contraseña, tipo_usuario } = req.body;

    try {
        if (!nombre_usuario || !contraseña || !tipo_usuario) {
            console.log("Campos vacíos:", req.body);
            return res.status(400).send("Faltan datos");
        }

        // Encriptar contraseña
        const hash = await bcrypt.hash(contraseña, 10);

        // Usar backticks para evitar problemas con la Ñ
        const sql = `
            INSERT INTO usuarios (\`nombre_usuario\`, \`contraseña\`, \`tipo_usuario\`)
            VALUES (?, ?, ?)
        `;

        connection.query(sql, [nombre_usuario, hash, tipo_usuario], (err, result) => {
            if (err) {
                console.error("Error registrando usuario:", err);
                return res.status(500).send("Error al registrar usuario");
            }

            res.redirect('/login.html');
        });

    } catch (error) {
        console.error(error);
        res.status(500).send("Error interno del servidor");
    }
});

// Mostrar página de usuarios
app.get('/api/usuarios', requireLogin, requireRole('admin'), (req, res) => {
  connection.query("SELECT id, nombre_usuario, tipo_usuario FROM usuarios", (err, results) => {
    if (err) return res.status(500).send("Error obteniendo usuarios");
    res.json(results);
  });
});

// Ruta: Contar cuántos usuarios hay por tipo de usuario (versión HTML con Bootstrap)
app.get('/usuarios/count-by-type', requireLogin, requireRole('admin'), (req, res) => {

  const sql = `
    SELECT tipo_usuario AS tipo, COUNT(*) AS total
    FROM usuarios
    GROUP BY tipo_usuario;
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.send('Error al obtener el conteo de usuarios.');
    }

    // Crear tabla HTML con Bootstrap
    let html = `
      <html>
      <head>
        <title>Conteo de Usuarios por Tipo</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>

      <body class="bg-light">

        <div class="container mt-5">
          <div class="card shadow">
            <div class="card-header bg-primary text-white">
              <h3 class="mb-0">Conteo de Usuarios por Tipo</h3>
            </div>

            <div class="card-body">
              <table class="table table-bordered table-striped">
                <thead class="table-dark">
                  <tr>
                    <th>Tipo de Usuario</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
    `;

    // Agregar filas dinámicas
    results.forEach(row => {
      html += `
        <tr>
          <td>${row.tipo}</td>
          <td>${row.total}</td>
        </tr>
      `;
    });

    html += `
                </tbody>
              </table>

              <a href="/gestionar-usuarios.html" class="btn btn-secondary mt-3">Regresar</a>
            </div>
          </div>
        </div>

      </body>
      </html>
    `;

    res.send(html);
  });
});

// Búsqueda de usuarios en tiempo real (por nombre_usuario o ID)
app.get('/api/usuarios/buscar', requireLogin, requireRole('admin'), (req, res) => {
  const query = req.query.query || '';

  let sql;
  let params;

  // Si lo que se escribe es un número → buscar por ID
  if (!isNaN(query) && query.trim() !== '') {
    sql = `
      SELECT id, nombre_usuario, tipo_usuario
      FROM usuarios
      WHERE id = ?
    `;
    params = [query];
  } 
  // Si es texto → buscar por nombre_usuario
  else {
    sql = `
      SELECT id, nombre_usuario, tipo_usuario
      FROM usuarios
      WHERE nombre_usuario LIKE ?
    `;
    params = [`%${query}%`];
  }

  connection.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error buscando usuarios:", err);
      return res.status(500).json({ error: "Error en la consulta" });
    }
    res.json(results);
  });
});

// Editar usuario (mostrar formulario)
app.post('/admin/usuarios/editar/:id', requireLogin, requireRole('admin'), (req, res) => {
    const id = req.params.id;
    const { nombre_usuario, tipo_usuario } = req.body;

    const sql = `
        UPDATE usuarios 
        SET nombre_usuario = ?, tipo_usuario = ?
        WHERE id = ?
    `;

    connection.query(sql, [nombre_usuario, tipo_usuario, id], (err) => {
        if (err) {
            console.error("Error actualizando usuario:", err);
            return res.status(500).send("Error al actualizar");
        }

        res.status(200).send("OK");
    });
});

// Eliminar usuario
app.post('/admin/usuarios/eliminar/:id', requireLogin, requireRole('admin'), (req, res) => {
  const userId = req.params.id;

  connection.query('DELETE FROM usuarios WHERE id = ?', [userId], (err) => {
    if (err) {
      console.error("Error eliminando usuario:", err);
      return res.status(500).send('Error al eliminar usuario');
    }

    // Enviar al listado
    res.redirect('/gestionar-Usuarios.html');
  });
});


/////PACIENTEEEEEEEEE//////
// Agregar paciente
app.post('/pacientes/agregar', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const { nombre, apellido, fecha_nacimiento, sexo } = req.body;

  connection.query(
    'INSERT INTO pacientes (nombre, apellido, fecha_nacimiento, sexo) VALUES (?, ?, ?, ?)',
    [nombre, apellido, fecha_nacimiento, sexo],
    (err) => {
      if (err) {
        console.error('Error insertando paciente:', err);
        return res.status(500).send('Error al registrar al paciente');
      }
      res.redirect('/');
    }
  );
});

//Ver pacientes
app.get('/api/pacientes', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  connection.query('SELECT * FROM pacientes', (err, results) => {
    if (err) return res.status(500).send("Error cargando pacientes");
    res.json(results);
  });
});

//Editar pacientes
app.post('/pacientes/editar/:id', requireLogin, requireRole('admin','recepcionista','laboratorista'),  (req, res) => {
  const { id } = req.params;
  const { nombre, apellido, fecha_nacimiento, sexo } = req.body;

  connection.query(
    "UPDATE pacientes SET nombre=?, apellido=?, fecha_nacimiento=?, sexo=? WHERE id=?",
    [nombre, apellido, fecha_nacimiento, sexo, id],
    (err) => {
      if (err) return res.status(500).send("Error editando paciente");
      res.sendStatus(200);
    }
  );
});

// Contar todos los pacientes
app.get('/pacientes/count', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const sql = "SELECT COUNT(*) AS total_pacientes FROM pacientes";

  connection.query(sql, (err, results) => {
    if (err) return res.status(500).send("Error al obtener conteo");
    res.json(results[0]);
  });
});

// Contar pacientes agrupados por sexo
app.get('/pacientes/count-by-sex', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const sql = `
    SELECT sexo, COUNT(*) AS total 
    FROM pacientes 
    GROUP BY sexo
  `;

  connection.query(sql, (err, results) => {
    if (err) return res.status(500).send("Error al obtener conteo por sexo");
    res.json(results);
  });
});


// Busqueda pacientes tiempo real (por nombre_usuario o ID)
app.get('/api/pacientes/buscar', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const query = req.query.query || '';

  let sql;
  let params;

  // Si el usuario ingresó un número → buscar por ID
  if (!isNaN(query) && query.trim() !== '') {
    sql = `
      SELECT id, nombre, apellido, fecha_nacimiento, sexo
      FROM pacientes
      WHERE id = ?
    `;
    params = [query];
  } 
  // Si ingresó texto → buscar por nombre o apellido
  else {
    sql = `
      SELECT id, nombre, apellido, fecha_nacimiento, sexo
      FROM pacientes
      WHERE nombre LIKE ? OR apellido LIKE ?
    `;
    params = [`%${query}%`, `%${query}%`];
  }

  connection.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error buscando pacientes:", err);
      return res.status(500).json({ error: "Error en la consulta" });
    }
    res.json(results);
  });
});


//Eliminar pacientes
app.post('/pacientes/eliminar/:id',requireLogin,requireRole('admin','recepcionista','laboratorista'),(req, res) => {

    const id = Number(req.params.id);

    if (isNaN(id)) {
      console.log("ID inválido recibido:", req.params.id);
      return res.status(400).send("ID inválido");
    }

    connection.query(
      "DELETE FROM pacientes WHERE id = ?",
      [id],
      (err, result) => {

        if (err) {
          console.log("Error eliminando paciente:", err);
          return res.status(500).send("Error eliminando paciente");
        }

        if (result.affectedRows === 0) {
          return res.status(404).send("Paciente no encontrado");
        }

        res.redirect('/gestionar-pacientes.html');
      }
    );
});

//MEDICOOOOOO
//Agregar medico
app.post('/medicos/agregar', requireLogin,requireRole('admin'), (req, res) => {
  const { nombre, apellido, especialidad, correo, sueldo } = req.body;

  const sql = `
      INSERT INTO medicos (nombre, apellido, especialidad, correo, sueldo) 
      VALUES (?, ?, ?, ?, ?)
  `;

  connection.query(sql, [nombre, apellido, especialidad, correo, sueldo], (err, result) => {
    if (err) {
      console.error("Error insertando médico:", err);
      return res.status(500).send("Error en el servidor");
    }

    res.redirect('/');
  });
});

//Ver medicos
app.get('/api/medicos', requireLogin, requireRole('admin'), (req, res) => {
  connection.query('SELECT * FROM medicos', (err, results) => {
    if (err) return res.status(500).send("Error cargando médicos");
    res.json(results);
  });
});

//Buscar medicos en tiempo real (por nombre, apellido, especialidad, correo o ID)
app.get('/api/medicos/buscar', requireLogin, requireRole('admin'), (req, res) => {
  const q = req.query.query || "";

  connection.query(
    `SELECT * FROM medicos 
     WHERE nombre LIKE ? 
        OR apellido LIKE ? 
        OR especialidad LIKE ?
        OR correo LIKE ?
        OR id LIKE ?`,
    [`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`],
    (err, results) => {
      if (err) return res.status(500).send("Error buscando médicos");
      res.json(results);
    }
  );
});

//Editar médicos
app.post('/medicos/editar/:id', requireLogin, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  const { nombre, apellido, especialidad, correo, sueldo } = req.body;

  connection.query(
    `UPDATE medicos SET 
        nombre = ?, 
        apellido = ?, 
        especialidad = ?, 
        correo = ?, 
        sueldo = ?
     WHERE id = ?`,
    [nombre, apellido, especialidad, correo, sueldo, id],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error al actualizar médico");
      }
      res.sendStatus(200);
    }
  );
});

//Eliminar médicos
app.post('/medicos/eliminar/:id', requireLogin, requireRole('admin'), (req, res) => {
  const id = req.params.id;

  connection.query(
    `DELETE FROM medicos WHERE id = ?`,
    [id],
    (err, results) => {
      if (err) return res.status(500).send("Error al eliminar médico");
      res.redirect('/gestionar-medicos.html');  // o donde esté tu vista
    }
  );
});

//CITAAAAAS
//Agregar cita
app.post('/citas/agregar', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const { paciente_id, medico_id, fecha_cita, motivo, estado } = req.body;

  // Verificar si ya existe una cita en esa fecha y hora
  const queryVerificar = `
    SELECT * FROM citas 
    WHERE fecha_cita = ?
  `;

  connection.query(queryVerificar, [fecha_cita], (err, resultados) => {
    if (err) {
      console.error('Error verificando citas:', err);
      return res.status(500).send("Error interno del servidor");
    }

    if (resultados.length > 0) {
      return res.status(400).send("Ya existe una cita programada en esa fecha y hora.");
    }

    // Registrar cita
    const queryInsertar = `
      INSERT INTO citas (paciente_id, fecha_cita, motivo, estado)
      VALUES (?, ?, ?, ?)
    `;

    connection.query(queryInsertar, [paciente_id, fecha_cita, motivo, estado], (err, result) => {
      if (err) {
        console.error('Error agregando cita:', err);
        return res.status(500).send("Error al registrar la cita");
      }

      res.redirect('/');
    });
  });
});

//Ver citas
app.get('/api/citas', requireLogin, requireRole('admin','recepcionista','laboratorista'),(req, res) => {
  const query = `
    SELECT 
      citas.id,
      pacientes.nombre AS paciente_nombre,
      citas.fecha_cita,
      citas.motivo,
      citas.estado,
      citas.fecha_registro
    FROM citas
    JOIN pacientes ON citas.paciente_id = pacientes.id
  `;

  connection.query(query, (err, results) => {
    if (err) return res.status(500).send("Error obteniendo citas");
    res.json(results);
  });
});

// Búsqueda de citas en tiempo real (por ID cita, ID paciente, nombre o estado)
app.get('/api/citas/buscar', requireLogin, requireRole('admin','recepcionista','laboratorista'), (req, res) => {
  const query = req.query.query || '';

  let sql;
  let params;

  // Si el query es número → buscar por ID cita o ID paciente
  if (!isNaN(query) && query.trim() !== '') {
    sql = `
      SELECT c.id, c.paciente_id, c.fecha_cita, c.motivo, c.estado, c.fecha_registro,
             p.nombre AS paciente_nombre
      FROM citas c
      LEFT JOIN pacientes p ON c.paciente_id = p.id
      WHERE c.id = ?
         OR c.paciente_id = ?
    `;
    params = [query, query];
  }
  // Buscar por texto (nombre paciente o estado)
  else {
    sql = `
      SELECT c.id, c.paciente_id, c.fecha_cita, c.motivo, c.estado, c.fecha_registro,
             p.nombre AS paciente_nombre
      FROM citas c
      LEFT JOIN pacientes p ON c.paciente_id = p.id
      WHERE p.nombre LIKE ?
         OR c.estado LIKE ?
    `;
    params = [`%${query}%`, `%${query}%`];
  }

  connection.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error buscando citas:", err);
      return res.status(500).json({ error: "Error en la consulta" });
    }
    res.json(results);
  });
});


//Editar citas
app.post('/citas/editar/:id', requireLogin, requireRole('admin','recepcionista'),(req, res) => {
  const { id } = req.params;
  const { fecha_cita, motivo, estado } = req.body;

  connection.query(
      "UPDATE citas SET fecha_cita=?, motivo=?, estado=? WHERE id=?",
      [fecha_cita, motivo, estado, id],
      (err) => {
        if (err) return res.status(500).json({
            ok: false,
            mensaje: "Error al actualizar la cita"
        });

        return res.json({
            ok: true,
            mensaje: "Cita actualizada correctamente"
        });
      }
  );
});

//Eliminar citas
app.post('/citas/eliminar/:id', requireLogin, requireRole('admin','recepcionista'),(req, res) => {
  connection.query(
    "DELETE FROM citas WHERE id=?",
    [req.params.id],
    (err) => {
      if (err) return res.status(500).send("Error eliminando cita");
      res.redirect('/gestionar-citas.html');
    }
  );
});

// RUTA PARA GUARDAR RESULTADOS BÁSICOS
app.post('/resultados-basicos/agregar',requireLogin, requireRole('laboratorista', 'admin'), (req, res) => {

    const {
        paciente_id,
        cita_id,
        hemoglobina,
        hematocrito,
        globulos_rojos,
        globulos_blancos,
        plaquetas,
        neutrofilos,
        linfocitos,
        glucosa,
        creatinina,
        urea,
        alt,
        ast,
        colesterol_total,
        trigliceridos,
        sodio,
        potasio
    } = req.body;

    const laboratorista_id = req.session.user.id;

    // Validación mínima
    if (!paciente_id || !cita_id) {
        return res.json({ ok: false, mensaje: "Faltan datos obligatorios" });
    }

    const sql = `
        INSERT INTO resultados_basicos (
            paciente_id, cita_id, laboratorista_id,
            hemoglobina, hematocrito, globulos_rojos, globulos_blancos,
            plaquetas, neutrofilos, linfocitos,
            glucosa, creatinina, urea, alt, ast,
            colesterol_total, trigliceridos, sodio, potasio
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    connection.query(sql, [
        paciente_id, cita_id, laboratorista_id,
        hemoglobina, hematocrito, globulos_rojos, globulos_blancos,
        plaquetas, neutrofilos, linfocitos,
        glucosa, creatinina, urea, alt, ast,
        colesterol_total, trigliceridos, sodio, potasio
    ],
    (err, result) => {
        if (err) {
            console.error(err);
            return res.json({ ok: false, mensaje: "Error al guardar resultado" });
        }

        res.json({ ok: true, mensaje: "Resultados guardados correctamente" });
    });
});

//Ruta para obtener el paciente asociado a una cita
app.get('/api/cita/:id',requireRole('laboratorista', 'admin','paciente'), (req, res) => {
    const id = req.params.id;

    const sql = `
        SELECT c.id, c.paciente_id, p.nombre AS paciente_nombre
        FROM citas c
        INNER JOIN pacientes p ON c.paciente_id = p.id
        WHERE c.id = ?
    `;

    connection.query(sql, [id], (err, rows) => {
        if (err) {
            console.error(err);
            return res.json({ ok: false, mensaje: "Error en BD" });
        }

        if (rows.length === 0) {
            return res.json({ ok: false, mensaje: "Cita no encontrada" });
        }

        return res.json({
            ok: true,
            paciente: {
                id: rows[0].paciente_id,
                nombre: rows[0].paciente_nombre
            }
        });
    });
});

//RESULTADOOOS
app.post("/descargar-resultados", requireRole('admin','recepcionista','paciente'),(req, res) => {
    const { paciente_id } = req.body;

    if (!paciente_id) {
        return res.json({ ok: false, mensaje: "Debes ingresar tu ID de paciente." });
    }

    // Consulta para conocer si existe el paciente
    const sqlPaciente = `
        SELECT id, nombre, apellido, fecha_nacimiento, sexo 
        FROM pacientes 
        WHERE id = ?
    `;

    connection.query(sqlPaciente, [paciente_id], (err, pacienteRes) => {
        if (err) {
            console.error(err);
            return res.json({ ok: false, mensaje: "Error en la base de datos (paciente)." });
        }

        if (pacienteRes.length === 0) {
            return res.json({ ok: false, mensaje: "Paciente no encontrado." });
        }

        const paciente = pacienteRes[0];

        // Consulta de resultados registrados para este paciente
        const sqlResultados = `
            SELECT *
            FROM resultados_basicos
            WHERE paciente_id = ?
            ORDER BY fecha_registro DESC
        `;

        connection.query(sqlResultados, [paciente_id], (err, resultadosRes) => {
            if (err) {
                console.error(err);
                return res.json({ ok: false, mensaje: "Error obteniendo resultados." });
            }

            if (resultadosRes.length === 0) {
                return res.json({ ok: false, mensaje: "No hay resultados registrados para este paciente." });
            }

            return res.json({
                ok: true,
                mensaje: "Datos encontrados",
                paciente: paciente,
                resultados: resultadosRes
            });
        });
    });
});

//Descargar PDF de resultados
app.get("/descargar-pdf/:paciente_id", requireRole('paciente'),(req, res) => {
    const paciente_id = req.params.paciente_id;

    if (!paciente_id) {
        return res.status(400).json({ ok: false, mensaje: "Falta ID del paciente" });
    }

    // Consulta paciente
    const sqlPaciente = `
        SELECT id, nombre, apellido, fecha_nacimiento, sexo 
        FROM pacientes
        WHERE id = ?
    `;

    connection.query(sqlPaciente, [paciente_id], (err, pacienteRes) => {
        if (err) return res.json({ ok: false, mensaje: "Error en DB (paciente)" });

        if (pacienteRes.length === 0)
            return res.json({ ok: false, mensaje: "Paciente no encontrado" });

        const paciente = pacienteRes[0];

        // Consulta resultados
        const sqlResultados = `
            SELECT *
            FROM resultados_basicos
            WHERE paciente_id = ?
            ORDER BY fecha_registro DESC
        `;

        connection.query(sqlResultados, [paciente_id], (err, resultadosRes) => {
            if (err) return res.json({ ok: false, mensaje: "Error obteniendo resultados" });

            if (resultadosRes.length === 0)
                return res.json({ ok: false, mensaje: "No hay resultados disponibles" });

            // --- GENERAR PDF ---
            const doc = new PDFDocument({ margin: 40 });

            const filename = `Resultados_Paciente_${paciente_id}.pdf`;
            res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
            res.setHeader("Content-Type", "application/pdf");

            doc.pipe(res);

            // === LOGO ===
            const logoPath = path.join(__dirname, "public/img/logo.png");
            if (fs.existsSync(logoPath)) {
                doc.image(logoPath, 40, 30, { width: 100 });
            }

            doc.fontSize(20).text("Resultados de Laboratorio", 150, 40);
            doc.moveDown();

            // === DATOS DEL PACIENTE ===
            doc.fontSize(14).text("Datos del Paciente", { underline: true });
            doc.moveDown(0.5);

            doc.fontSize(12)
                .text(`Nombre: ${paciente.nombre} ${paciente.apellido}`)
                .text(`Fecha de nacimiento: ${paciente.fecha_nacimiento}`)
                .text(`Sexo: ${paciente.sexo}`)
                .moveDown();

            // === TABLA DE RESULTADOS ===
            doc.fontSize(14).text("Resultados Registrados", { underline: true });
            doc.moveDown(0.5);

            resultadosRes.forEach((r, i) => {
                doc.fontSize(12)
                    .text(`Fecha registro: ${r.fecha_registro}`)
                    .text(`Hemoglobina: ${r.hemoglobina ?? "-"}`)
                    .text(`Hematocrito: ${r.hematocrito ?? "-"}`)
                    .text(`Glóbulos Rojos: ${r.globulos_rojos ?? "-"}`)
                    .text(`Glóbulos Blancos: ${r.globulos_blancos ?? "-"}`)
                    .text(`Plaquetas: ${r.plaquetas ?? "-"}`)
                    .text(`Neutrófilos: ${r.neutrofilos ?? "-"}`)
                    .text(`Linfocitos: ${r.linfocitos ?? "-"}`)
                    .text(`Glucosa: ${r.glucosa ?? "-"}`)
                    .text(`Creatinina: ${r.creatinina ?? "-"}`)
                    .text(`Urea: ${r.urea ?? "-"}`)
                    .text(`ALT: ${r.alt ?? "-"}`)
                    .text(`AST: ${r.ast ?? "-"}`)
                    .text(`Colesterol Total: ${r.colesterol_total ?? "-"}`)
                    .text(`Triglicéridos: ${r.trigliceridos ?? "-"}`)
                    .text(`Sodio: ${r.sodio ?? "-"}`)
                    .text(`Potasio: ${r.potasio ?? "-"}`)
                    .moveDown();

                if (i < resultadosRes.length - 1) doc.addPage();
            });

            doc.end();
        });
    });
});

//RUTAS PARA EXCEL
// Ruta para la descarga del archivo Excel de pacientes
app.get('/download-pacientes', requireLogin, requireRole('admin','recepcionista'), (req, res) => {
  const sql = `
    SELECT 
      nombre,
      apellido,
      DATE_FORMAT(fecha_nacimiento, '%Y-%m-%d') AS fecha_nacimiento,
      sexo
    FROM pacientes
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error al obtener pacientes:", err);
      return res.status(500).send("Error en el servidor");
    }

    // Crear Excel
    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Pacientes');

    const filePath = path.join(__dirname, 'uploads', 'pacientes.xlsx');
    xlsx.writeFile(workbook, filePath);

    res.download(filePath, 'pacientes.xlsx');
  });
});


// Ruta para subir archivo Excel e insertar pacientes
app.post('/upload-pacientes', upload.single('excelFile'),requireRole('admin','recepcionista'), (req, res) => {
  const filePath = req.file.path;

  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  data.forEach(row => {
    const { nombre, apellido, fecha_nacimiento, sexo } = row;

    if (!nombre || !apellido || !fecha_nacimiento || !sexo) {
      console.log("Fila incompleta:", row);
      return;
    }

    const sql = `
      INSERT INTO pacientes (nombre, apellido, fecha_nacimiento, sexo)
      VALUES (?, ?, ?, ?)
    `;

    connection.query(sql, [nombre, apellido, fecha_nacimiento, sexo], (err) => {
      if (err) console.error("Error insertando paciente:", err);
    });
  });

  res.send(`
    <h2>Archivo Excel cargado correctamente</h2>
    <a href="/">Regresar</a>
  `);
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
}); 
