const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const app = express();
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const upload = multer({ dest: 'uploads/' });
require('dotenv').config();
const fs = require('fs');
const PDFDocument = require('pdfkit');
const PORT = process.env.PORT;
const util = require('util');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Solo se permiten archivos PDF.'), false);
  }
};

const uploadPDF = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
      if (req.session.user && role.includes(req.session.user.tipo_usuario)) {
          next();
      } else {
        
          console.log('Error al encontrar el rol del usuario')
          res.status(403).send('no autorizado.');
      }
  };
}

function navbar(tipo_usuario) {
  const opciones = [
    { ruta: '/', texto: 'Inicio', roles: ['admin','médico','ingeniero','paciente'] },
    { ruta: '/usuarios', texto: 'Usuarios', roles: ['admin'] },
    { ruta: '/gestionar', texto: 'Gestionar', roles: ['admin'] },
    { ruta: '/mis-equipos', texto: 'Mis equipos', roles: ['médico'] },
    { ruta: '/mis-pacientes', texto: 'Mis pacientes', roles: ['médico'] },
    { ruta: '/pacientes', texto: 'Pacientes', roles: ['médico'] },
    { ruta: '/equipos', texto: 'Equipos', roles: ['ingeniero'] },
    { ruta: '/medicos', texto: 'Ver médicos', roles: ['paciente', 'ingeniero'] },
    { ruta: '/ver-mis-datos', texto: 'Ver mis datos', roles: ['pacientes'] },
    { ruta: '/logout', texto: 'Cerrar sesión', roles: ['admin','médico','ingeniero','paciente'] },
  ];

  const itemsNavbar = opciones
    .filter(opcion => opcion.roles?.includes(tipo_usuario))
    .map(opcion => `<li class="nav-menu-item"><a href="${opcion.ruta}" class="nav-link">${opcion.texto}</a></li>`)
    .join('');

  return `
    <header class="header">
      <nav class="nav">
        <ul class="nav-menu">
          ${itemsNavbar}
        </ul>
      </nav>
    </header>
  `;
}

app.get('/registrar', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registro.html'));
});

app.post('/registrar', (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;

  connection.beginTransaction(err => {
    if (err) {
      console.error('Error al iniciar la transacción:', err);
      return res.status(500).send('Error al procesar la solicitud');
    }

    const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?;';
    connection.query(query, [codigo_acceso], (err, results) => {
      if (err || results.length === 0) {
        return connection.rollback(() => {
          console.error('Error al validar el código de acceso:', err);
          let html = `
          <html>
          <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Error</title>
          </head>
          <body>
            <h1>Error: tipo de usuario inválido</h1> 
            <button onclick="window.location.href='/'">Volver</button>
          </body>
          </html>
          `;
          return res.send(html);
        });
      }

      const tipo_usuario = results[0].tipo_usuario;
      const passwordHash = bcrypt.hashSync(password, 10);
      const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';

      connection.query(insertUser, [nombre_usuario, passwordHash, tipo_usuario], err => {
        if (err) {
          return connection.rollback(() => {
            console.error('Error al insertar el usuario:', err);
            let html = `
            <html>
            <head>
              <link rel="stylesheet" href="/styles.css">
              <title>Error</title>
            </head>
            <body>
              <h1>Error al registrar al usuario</h1> 
              <button onclick="window.location.href='/'">Volver</button>
            </body>
            </html>
            `;
            return res.send(html);
          });
        }

        connection.commit(err => {
          if (err) {
            return connection.rollback(() => {
              console.error('Error al realizar el commit:', err);
              return res.status(500).send('Error al procesar la solicitud');
            });
          }

          return res.redirect('/login');
        });
      });
    });
  });
});


app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  console.log(req.body);
  const { nombre_usuario, password } = req.body;

  const query = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  connection.query(query, [nombre_usuario], (err, results) => {
      if (err) {
          return res.send('Error al obtener el usuario');
      }

      if (results.length === 0) {
          return res.send('Usuario no encontrado');
      }

      const user = results[0];

      const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
      if (!isPasswordValid) {
          return res.send('Contraseña incorrecta');
      }

      req.session.user = {
          id: user.id,
          nombre_usuario: user.nombre_usuario,
          tipo_usuario: user.tipo_usuario 
      };
      res.redirect('/');
  });
});

app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}); 

app.use(express.static(path.join(__dirname, 'public')));

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

app.get('/usuarios', requireLogin, requireRole('admin'), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);

  let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Usuarios</title>
    </head>
    <body>
    <div id="navbar">
        ${navbarHtml}
    </div>
    <main>
      <h1>Usuarios Registrados</h1>
      <input type="text" id="search" placeholder="Buscar usuarios..." />
      <table>
        <thead>
          <tr>
            <th>Id</th>
            <th>Nombre</th>
            <th>Tipo de usuario</th>
          </tr>
        </thead>
        <tbody id="users-table">
        </tbody>
      </table>
      <button onclick="window.location.href='/'">Volver</button>
    </main>
    <script>
      function searchusers(query) {
        fetch(\`/buscar-usuarios?query=\${query}\`)
          .then(response => response.json())
          .then(data => {
            const tableBody = document.getElementById('users-table');
            tableBody.innerHTML = '';

            data.forEach(usuario => {
              const row = document.createElement('tr');
              row.innerHTML = \`
                <td>\${usuario.id}</td>
                <td>\${usuario.nombre_usuario}</td>
                <td>\${usuario.tipo_usuario}</td>
              \`;
              tableBody.appendChild(row);
            });
          })
          .catch(err => {
            console.error('Error al buscar usuarios:', err);
          });
      }
      const searchInput = document.getElementById('search');
      searchInput.addEventListener('input', (event) => {
        const query = event.target.value;
        searchusers(query); 
      });

      searchusers('');
    </script>
    </body>
    </html>
  `;
  res.send(html);
});

app.get('/buscar-usuarios', requireLogin, requireRole('admin'), (req, res) => {
  const query = req.query.query || ''; 
  const sql = `SELECT * FROM usuarios WHERE nombre_usuario LIKE ?`; 
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) {
      console.error('Error al buscar usuarios:', err.message);
      return res.status(500).json({ error: 'Error al buscar usuarios' });
    }
    res.json(results); 
  });
});

app.get('/gestionar', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'gestionar.html'));
}); 

app.post('/gestionar', requireLogin, requireRole(['admin', 'ingeniero']), (req, res) => {
  console.log(req.body);
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { tabla, id, columna, nvalor } = req.body;
  const query = 'UPDATE ?? SET ?? = ? WHERE id = ?';
  connection.query(query, [tabla, columna, nvalor, id], (err, result) => {
    if (err) {
      let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Error</title>
        </head>
        <body>
        <div id="navbar">
          ${navbarHtml}
        </div>
        <h1>Error al modificar el registro en la base de datos</h1> 
        <button onclick="window.location.href='/'">Volver</button>
        </body>
        </html>
      `;
      return res.send(html);
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Registro actualizado</title>
      </head>
      <body>
      <div id="navbar">
        ${navbarHtml}
      </div>
      <main>
        <h1>Registro actualizado exitosamente en la base de datos</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </main>
      </body>
      </html>
    `;
    return res.send(html); 
  });
});

app.get('/ver-mis-datos', requireLogin, requireRole('pacientes'), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const nombre_usuario = req.session.user.nombre_usuario;
  connection.query(`SELECT * FROM vista_pacientes_medicos WHERE nombre_paciente LIKE '%${nombre_usuario}%'`, (err, results) => {
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al obtener los datos:(</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente</title>
      </head>
      <body>
      <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>apellido</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
              <th>Altura (m)</th>
              <th>Peso (kg)</th>
              <th>Médico asignado</th>
            </tr>
          </thead>
          <tbody>
    `;
    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre_paciente}</td>
          <td>${paciente.apellido}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
          <td>${paciente.altura}</td>
          <td>${paciente.peso}</td>
          <td>${paciente.nombre_medico}</td>
        </tr>
      `;
    });
    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  });
});

app.post('/submit-data', requireLogin, (req, res) => {
  console.log(req.body); 

  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { name, sname, age, heart_rate, height, weight, id_ma } = req.body;

  if (!name || !sname || !age || !heart_rate || !height || !weight || !id_ma) {
      return res.status(400).send('Faltan datos en el formulario');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const query = 'INSERT INTO pacientes (nombre_paciente, apellido, edad, peso, altura, frecuencia_cardiaca, id_ma) VALUES (?, ?, ?, ?, ?, ?, ?)';
      connection.query(query, [name, sname, age, weight, height, heart_rate, id_ma], (err, result) => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  let html = `
                  <html>
                  <head>
                      <link rel="stylesheet" href="/styles.css">
                      <title>Error</title>
                  </head>
                  <body>
                      <div id="navbar">${navbarHtml}</div>
                      <main>
                      <h1>Error al guardar el paciente en la base de datos</h1> 
                      <button onclick="window.location.href='/'">Volver</button>
                      </main>
                  </body>
                  </html>
                  `;
                  return res.send(html);
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Paciente guardado</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                  <h1>Paciente guardado exitosamente</h1>
                  <table>
                      <thead>
                          <tr>
                              <th>Nombre</th>
                              <th>Apellido</th>
                              <th>Edad</th>
                              <th>Frecuencia Cardiaca (bpm)</th>
                              <th>Altura (m)</th>
                              <th>Peso (kg)</th>
                          </tr>
                      </thead>
                      <tbody>
                          <tr>
                              <td>${name}</td>
                              <td>${sname}</td>
                              <td>${age}</td>
                              <td>${heart_rate}</td>
                              <td>${height}</td>
                              <td>${weight}</td>
                          </tr>
                      </tbody>
                  </table>
                  <button onclick="window.location.href='/'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});


app.post('/eliminar-registros', requireLogin, requireRole('admin'), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { registro, id } = req.body;
  const query = 'DELETE FROM ?? WHERE id = ?';
  connection.query(query, [registro, id], (err, result) => {
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
   <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al eliminar el registro</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }

    let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Registro eliminado</title>
    </head>
    <body>
   <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Registro eliminado exitosamente</h1>
      <button onclick="window.location.href='/'">Volver al menú principal</button>
    </body>
    </html>
  `;
  return res.send(html);
});
});

app.get('/pacientes', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario; 
  const navbarHtml = navbar(tipo_usuario); 

  const html = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Pacientes</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <div id="navbar">${navbarHtml}</div>
      <main>
        <h1>Pacientes Registrados</h1>
        <input type="text" id="search" placeholder="Buscar pacientes..." />
        <select id="filter">
          <option value="all">Todos los pacientes</option>
          <option value="a_sort">Ordenar alfabéticamente</option>
          <option value="avg_all">Promedios generales</option>
          <option value="medic_alph">Ordenar por médico</option>
          <option value="avg_height">Altura promedio por médico</option>
          <option value="avg_weight">Peso promedio por médico</option>
          <option value="avg_f_c">Frecuencia cardiaca promedio</option>
          <option value="avg_age">Edad promedio</option>
          <option value="total_patients">Pacientes por médico</option>
        </select>
        <table>
          <thead>
            <tr>
              <th>Id</th>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
              <th>Altura (m)</th>
              <th>Peso (kg)</th>
              <th>Médico asignado</th>
            </tr>
          </thead>
          <tbody id="patients-table"></tbody>
        </table>
        <button onclick="window.location.href='/pacientes-x'">Cargar desde Excel</button>
        <button onclick="window.location.href='/pacientes-pdf'">Cargar desde PDF</button>
        <button onclick="window.location.href='/'">Volver</button>
      </main>
      <script>
        const tableBody = document.getElementById('patients-table');
        const filter = document.getElementById('filter');
        const searchInput = document.getElementById('search');

        async function filterTable() {
          try {
            const response = await fetch(\`/filtrar-pacientes?filter=\${encodeURIComponent(filter.value)}\`);
            if (!response.ok) throw new Error(\`Error del servidor: \${response.statusText}\`);
            const data = await response.json();
            renderTable(data);
          } catch (err) {
            console.error('Error al filtrar pacientes:', err);
            alert('Error al cargar los pacientes.');
          }
        }
        async function searchPatients(query) {
          try {
            const response = await fetch(\`/buscar-pacientes?query=\${encodeURIComponent(query)}\`);
            if (!response.ok) throw new Error(\`Error del servidor: \${response.statusText}\`);
            const data = await response.json();
            renderTable(data);
          } catch (err) {
            console.error('Error al buscar pacientes:', err);
            alert('Error al buscar pacientes.');
          }
        }

        function renderTable(data) {
          tableBody.innerHTML = '';
          data.forEach(paciente => {
            const row = document.createElement('tr');
            row.innerHTML = \`
              <td>\${paciente.id || '-'}</td>
              <td>\${paciente.nombre_paciente || '-'}</td>
              <td>\${paciente.edad || '-'}</td>
              <td>\${paciente.frecuencia_cardiaca || '-'}</td>
              <td>\${paciente.altura || '-'}</td>
              <td>\${paciente.peso || '-'}</td>
              <td>\${paciente.nombre_medico || '-'}</td>
            \`;
            tableBody.appendChild(row);
          });
        }

        filter.addEventListener('change', filterTable);
        searchInput.addEventListener('input', event => searchPatients(event.target.value));

        filterTable();
      </script>
    </body>
    </html>
  `;
  res.send(html);
});

app.get('/buscar-pacientes', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  const query = req.query.query || ''; 
  const sql = `SELECT * FROM vista_pacientes_medicos WHERE nombre_paciente LIKE ?`; 
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) {
      console.error('Error al buscar pacientes:', err.message);
      return res.status(500).json({ error: 'Error al buscar pacientes' });
    }
    res.json(results); 
  });
});

app.get('/filtrar-pacientes', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  const filter = req.query.filter || 'all';
  let sql;

  switch (filter) {
    case 'avg_all':
      sql = `
        SELECT AVG(edad) AS edad, AVG(peso) AS peso, AVG(altura) AS altura, AVG(frecuencia_cardiaca) AS frecuencia_cardiaca 
        FROM pacientes;
      `;
      break;

    case 'a_sort':
      sql = `
        SELECT * FROM vista_pacientes_medicos ORDER BY nombre_paciente ASC;
      `;
      break;

    case 'medic_alph':
      sql = `
        SELECT *
        FROM vista_pacientes_medicos 
        JOIN medicos ON vista_pacientes_medicos.id_ma = medicos.id
        ORDER BY medicos.nombre_medico ASC;
      `;
      break;

    case 'avg_weight':
      sql = `
        SELECT medicos.nombre_medico, AVG(pacientes.peso) AS peso
        FROM pacientes
        JOIN medicos ON pacientes.id_ma = medicos.id
        GROUP BY medicos.nombre_medico;
      `;
      break;

    case 'avg_height':
      sql = `
        SELECT medicos.nombre_medico, AVG(pacientes.altura) AS altura
        FROM pacientes
        JOIN medicos ON pacientes.id_ma = medicos.id
        GROUP BY medicos.nombre_medico;
      `;
      break;

    case 'avg_f_c':
      sql = `
        SELECT medicos.nombre_medico, AVG(pacientes.frecuencia_cardiaca) AS frecuencia_cardiaca
        FROM pacientes
        JOIN medicos ON pacientes.id_ma = medicos.id
        GROUP BY medicos.nombre_medico;
      `;
      break;

    case 'avg_age':
      sql = `
        SELECT medicos.nombre_medico, AVG(pacientes.edad) AS edad
        FROM pacientes
        JOIN medicos ON pacientes.id_ma = medicos.id
        GROUP BY medicos.nombre_medico;
      `;
      break;

    case 'total_patients':
      sql = `
        SELECT medicos.nombre_medico, COUNT(pacientes.id) AS id
        FROM pacientes
        JOIN medicos ON pacientes.id_ma = medicos.id
        GROUP BY medicos.nombre_medico;
      `;
      break;

    case 'all':
    default:
      sql = `SELECT * FROM vista_pacientes_medicos;`;
      break;
  }

  connection.query(sql, (err, results) => {
    if (err) {
      console.error('Error al filtrar pacientes:', err.message);
      return res.status(500).json({ error: 'Error al filtrar pacientes' });
    }
    res.json(results);
  });
});

app.get('/ordenar-pacientes', requireLogin, requireRole(['admin', 'médico']), (req, res) =>{
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const query = 'SELECT * FROM vista_pacientes_medicos ORDER BY nombre_paciente DESC';
  connection.query (query, (err,results) =>{
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al obtener los datos :(</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }

    let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Pacientes Ordenados</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Pacientes Ordenados por Frecuencia Cardiaca</h1>
      <table>
        <thead>
          <tr>
            <th>Nombre</th>
            <th>Edad</th>
            <th>Frecuencia Cardiaca (bpm)</th>
            <th>Altura (m)</th>
            <th>Peso (kg)</th>
            <th>Médico asignado</th>
          </tr>
        </thead>
        <tbody>
     `;
     results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre_paciente}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
          <td>${paciente.altura}</td>
          <td>${paciente.peso}</td>
          <td>${paciente.nombre_medico}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  })
})

app.get('/registrarme', requireLogin, requireRole('médico'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registrarme.html'));
}); 

app.post('/insertar-medico', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { medico_name, especialidad, id_hospital } = req.body;

  if (!medico_name || !especialidad || !id_hospital) {
      return res.status(400).send('Faltan datos en el formulario');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const query = 'INSERT INTO medicos (nombre_medico, especialidad, id_hospital) VALUES (?, ?, ?)';
      connection.query(query, [medico_name, especialidad, id_hospital], (err, result) => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  let html = `
                  <html>
                  <head>
                      <link rel="stylesheet" href="/styles.css">
                      <title>Error</title>
                  </head>
                  <body>
                      <div id="navbar">${navbarHtml}</div>
                      <main>
                      <h1>Error al guardar al médico en la base de datos</h1> 
                      <button onclick="window.location.href='/'">Volver</button>
                      </main>
                  </body>
                  </html>
                  `;
                  return res.send(html);
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Médico registrado</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                  <h1>Médico guardado exitosamente en la base de datos</h1>
                  <table>
                      <thead>
                          <tr>
                              <th>Nombre</th>
                              <th>Especialidad</th>
                          </tr>
                      </thead>
                      <tbody>
                          <tr>
                              <td>${medico_name}</td>
                              <td>${especialidad}</td>
                          </tr>
                      </tbody>
                  </table>
                  <button onclick="window.location.href='/'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});

app.get('/hospital', requireLogin, requireRole('admin'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'hospital.html'));
}); 

app.post('/hospital', requireLogin, requireRole(['admin']), (req, res) => {
  console.log(req.body);
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { hospital_name, ubicacion } = req.body;

  if (!hospital_name || !ubicacion) {
      return res.status(400).send('Faltan datos en el formulario');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const query = 'INSERT INTO hospital (nombre_hospital, ubicación) VALUES (?, ?)';
      connection.query(query, [hospital_name, ubicacion], (err, result) => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  let html = `
                  <html>
                  <head>
                      <link rel="stylesheet" href="/styles.css">
                      <title>Error</title>
                  </head>
                  <body>
                      <div id="navbar">${navbarHtml}</div>
                      <main>
                      <h1>Error al guardar el hospital en la base de datos</h1> 
                      <button onclick="window.location.href='/'">Volver</button>
                      </main>
                  </body>
                  </html>
                  `;
                  return res.send(html);
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Hospital registrado</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                  <h1>Hospital registrado exitosamente en la base de datos</h1>
                  <table>
                      <thead>
                          <tr>
                              <th>Nombre</th>
                              <th>Ubicación</th>
                          </tr>
                      </thead>
                      <tbody>
                          <tr>
                              <td>${hospital_name}</td>
                              <td>${ubicacion}</td>
                          </tr>
                      </tbody>
                  </table>
                  <button onclick="window.location.href='/'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});

app.get('/medicos', requireLogin, (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);

  let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Médicos</title>
    </head>
    <body>
    <div id="navbar">
        ${navbarHtml}
    </div>
    <main>
      <h1>Médicos Registrados</h1>
      <input type="text" id="search" placeholder="Buscar médicos..." />
      <table>
        <thead>
          <tr>
            <th>Nombre</th>
            <th>Especialidad</th>
            <th>Hospital</th>
          </tr>
        </thead>
        <tbody id="medico-table">
        </tbody>
      </table>
      <button onclick="window.location.href='/'">Volver</button>
    </main>
    <script>
      function searchMed(query) {
        fetch(\`/buscar-medicos?query=\${query}\`)
          .then(response => response.json())
          .then(data => {
            const tableBody = document.getElementById('medico-table');
            tableBody.innerHTML = '';

            data.forEach(medico => {
              const row = document.createElement('tr');
              row.innerHTML = \`
                <td>\${medico.nombre_medico}</td>
                <td>\${medico.especialidad}</td>
                <td>\${medico.nombre_hospital}</td>
              \`;
              tableBody.appendChild(row);
            });
          })
          .catch(err => {
            console.error('Error al buscar médicos:', err);
          });
      }
      const searchInput = document.getElementById('search');
      searchInput.addEventListener('input', (event) => {
        const query = event.target.value;
        searchMed(query); 
      });

      searchMed('');
    </script>
    </body>
    </html>
  `;
  res.send(html);
});

app.get('/buscar-medicos', requireLogin, (req, res) => {
  const query = req.query.query || ''; 
  const sql = `SELECT * FROM vista_medicos_hospitales WHERE nombre_medico LIKE ?`; 
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) {
      console.error('Error al buscar médicos:', err.message);
      return res.status(500).json({ error: 'Error al buscar médicos' });
    }
    res.json(results); 
  });
});

app.get('/g-equipos', requireLogin, requireRole(['admin', 'ingeniero']), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'g-equipos.html'));
}); 

app.post('/insertar-equipo', requireLogin, requireRole(['admin', 'ingeniero']), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);
  const { equipo_name, estado, descripcion, u_m, id_M, id_hospital } = req.body;

  if (!equipo_name || !estado || !descripcion || !u_m || !id_M || !id_hospital) {
      return res.status(400).send('Faltan datos en el formulario');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const query = 'INSERT INTO equipos (nombre_equipo, estado, descripcion, ultimo_mantenimiento, id_ma, id_hospital) VALUES (?, ?, ?, ?, ?, ?)';
      connection.query(query, [equipo_name, estado, descripcion, u_m, id_M, id_hospital], (err, result) => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  let html = `
                  <html>
                  <head>
                      <link rel="stylesheet" href="/styles.css">
                      <title>Error</title>
                  </head>
                  <body>
                      <div id="navbar">${navbarHtml}</div>
                      <main>
                      <h1>Error al guardar el equipo en la base de datos</h1> 
                      <button onclick="window.location.href='/'">Volver</button>
                      </main>
                  </body>
                  </html>
                  `;
                  return res.send(html);
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Equipo registrado</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                  <h1>Equipo guardado exitosamente en la base de datos</h1>
                  <table>
                      <thead>
                          <tr>
                              <th>Nombre</th>
                              <th>Estado</th>
                              <th>Descripción</th>
                              <th>Último mantenimiento</th>
                          </tr>
                      </thead>
                      <tbody>
                          <tr>
                              <td>${equipo_name}</td>
                              <td>${estado}</td>
                              <td>${descripcion}</td>
                              <td>${u_m}</td>
                          </tr>
                      </tbody>
                  </table>
                  <button onclick="window.location.href='/'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});

app.get('/equipos', requireLogin, requireRole('ingeniero'), (req, res) => {
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);

  let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Equipos</title>
    </head>
    <body>
    <div id="navbar">
        ${navbarHtml}
    </div>
    <main>
      <h1>Equipos Registrados</h1>
      <input type="text" id="search" placeholder="Buscar equipos..." />
      <table>
        <thead>
          <tr>
            <th>Id</th>
            <th>Nombre</th>
            <th>Estado</th>
            <th>Descripción</th>
            <th>Último mantenimiento</th>
            <th>Hospital</th>
            <th>Ubicación</th>
          </tr>
        </thead>
        <tbody id="equipos-table">
        </tbody>
      </table>
      <button onclick="window.location.href='/'">Volver</button>
    </main>
    <script>
      function searchEq(query) {
        fetch(\`/buscar-equipos?query=\${query}\`)
          .then(response => response.json())
          .then(data => {
            const tableBody = document.getElementById('equipos-table');
            tableBody.innerHTML = '';

            data.forEach(equipo => {
              const row = document.createElement('tr');
              row.innerHTML = \`
                <td>\${equipo.id}</td>
                <td>\${equipo.nombre_equipo}</td>
                <td>\${equipo.estado}</td>
                <td>\${equipo.descripcion}</td>
                <td>\${equipo.ultimo_mantenimiento}</td>
                <td>\${equipo.nombre_hospital}</td>
                <td>\${equipo.ubicación}</td>
              \`;
              tableBody.appendChild(row);
            });
          })
          .catch(err => {
            console.error('Error al buscar equipos:', err);
          });
      }
      const searchInput = document.getElementById('search');
      searchInput.addEventListener('input', (event) => {
        const query = event.target.value;
        searchEq(query); 
      });

      searchEq('');
    </script>
    </body>
    </html>
  `;
  res.send(html);
});

app.get('/buscar-equipos', requireLogin, (req, res) => {
  const query = req.query.query || ''; 
  const sql = `SELECT * FROM vista_equipos_hospitales WHERE nombre_equipo LIKE ?`; 
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) {
      console.error('Error al buscar equipos:', err.message);
      return res.status(500).json({ error: 'Error al buscar equipos' });
    }
    res.json(results); 
  });
});

app.get('/mis-pacientes', requireLogin, requireRole('médico'), (req, res) => {
  const { tipo_usuario, nombre_usuario } = req.session.user;
  const navbarHtml = navbar(tipo_usuario);
  connection.query(`SELECT * FROM vista_pacientes_medicos WHERE nombre_medico LIKE '%${nombre_usuario}%' `, (err, results) => {
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al obtener los datos:(</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente</title>
      </head>
      <body>
      <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
        <table>
          <thead>
            <tr>
              <th>Id</th>
              <th>Nombre</th>
              <th>Apellido</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
              <th>Altura (m)</th>
              <th>Peso (kg)</th>
            </tr>
          </thead>
          <tbody>
    `;
    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.id}</td>
          <td>${paciente.nombre_paciente}</td>
          <td>${paciente.apellido}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
          <td>${paciente.altura}</td>
          <td>${paciente.peso}</td>
        </tr>
      `;
    });
    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  });
});

app.get('/mis-equipos', requireLogin, requireRole('médico'), (req, res) => {
  const { tipo_usuario, nombre_usuario } = req.session.user;
  const navbarHtml = navbar(tipo_usuario);
  connection.query(`SELECT * FROM vista_equipos_medicos WHERE nombre_medico LIKE '%${nombre_usuario}%' `, (err, results) => {
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al obtener los datos:(</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Mis equipos</title>
      </head>
      <body>
      <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
        <table>
          <thead>
            <tr>
              <th>Id</th>
              <th>Nombre</th>
              <th>Estado</th>
              <th>Descripcion</th>
              <th>Ultimo mantenimiento</th>
            </tr>
          </thead>
          <tbody>
    `;
    results.forEach(equipo => {
      html += `
        <tr>
          <td>${equipo.id}</td>
          <td>${equipo.nombre_equipo}</td>
          <td>${equipo.estado}</td>
          <td>${equipo.descripcion}</td>
          <td>${equipo.ultimo_mantenimiento}</td>
        </tr>
      `;
    });
    
    return res.send(html);
  });
});

app.get('/pacientes-x', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  res.sendFile(__dirname + '/public/pacientes-x.html');
});

app.post('/upload-x', upload.single('excelFile'), requireRole(['admin', 'médico']), (req, res) => {
  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);

  if (!data || data.length === 0) {
      return res.status(400).send('El archivo Excel está vacío o no contiene datos válidos.');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const values = data.map(row => [
          row.nombre_paciente, 
          row.apellido, 
          row.edad, 
          row.peso, 
          row.altura, 
          row.frecuencia_cardiaca, 
          row.id_ma
      ]);

      const sql = `INSERT INTO pacientes (nombre_paciente, apellido, edad, peso, altura, frecuencia_cardiaca, id_ma) VALUES ?`;

      connection.query(sql, [values], err => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  return res.status(500).send('Error al cargar los datos desde el archivo Excel.');
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Datos subidos</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                      <h1>Los datos se han subido con éxito al servidor</h1>
                      <button onclick="window.location.href='/pacientes-x'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});

app.get('/download-x', requireRole(['admin', 'médico']), (req, res) => {
    const sql = `SELECT * FROM pacientes`;
    connection.query(sql, (err, results) => {
      if (err) throw err;
  
      const worksheet = xlsx.utils.json_to_sheet(results);
      const workbook = xlsx.utils.book_new();
      xlsx.utils.book_append_sheet(workbook, worksheet, 'pacientes');
  
      const filePath = path.join(__dirname, 'uploads', 'pacientes.xlsx');
      xlsx.writeFile(workbook, filePath);
      return res.download(filePath, 'pacientes.xlsx');
    });
});

app.get('/pacientes-pdf', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  res.sendFile(__dirname + '/public/pacientes-pdf.html');
});

app.post('/upload-pdf', requireLogin, requireRole('médico'), uploadPDF.single('pdfFile'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send('No se ha subido ningún archivo.');
    }

    const filename = req.file.filename;

    const sqlInsertFile = 'INSERT INTO archivos_pdf (nombre_archivo) VALUES (?)';

    connection.query(sqlInsertFile, [filename], (err) => {
      if (err) {
        console.error('Error al insertar en la base de datos:', err);
        return res.status(500).send('Hubo un error al guardar el archivo en la base de datos.');
      }

      res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Confirmación de carga</title>
          <link rel="stylesheet" href="styles.css">
        </head>
        <body>
          <div class="container">
            <h1>PDF cargado correctamente</h1>
            <p class="mensaje-exito">Archivo cargado correctamente</p>
            <div class="button-container">
              <button onclick="window.location.href='/'" class="buttonv">Volver</button>
            </div>
          </div>
        </body>
        </html>
      `);
    });
  } catch (error) {
    console.error('Error inesperado:', error);
    res.status(500).send('Ocurrió un error inesperado.');
  }
});

app.get('/download-pdf', requireLogin, requireRole('médico'), (req, res) => {
  const sql = 'SELECT * FROM pacientes';
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error al consultar la base de datos:", err);
      return res.status(500).send('Error al obtener los datos.');
    }

    const doc = new PDFDocument({ autoFirstPage: false }); 
    const filePath = path.join(__dirname, 'uploads', 'pacientes.pdf');
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    doc.addPage();

    doc.fontSize(14).text('Pacientes registrados', { align: 'center' }).moveDown();

    const tableHeaders = ['ID', 'Nombre', 'Apellido', 'Edad', 'Peso', 'Altura', 'Frecuencia Cardiaca'];
    const tableRows = results.map((paciente) => [
      paciente.id,
      paciente.nombre_paciente,
      paciente.apellido,
      paciente.edad,
      paciente.peso,
      paciente.altura,
      paciente.frecuencia_cardiaca,
    ]);

    const columnWidths = [50, 100, 100, 50, 50, 50, 150];

    let y = doc.y; 
    tableHeaders.forEach((header, i) => {
      doc.text(header, columnWidths.slice(0, i).reduce((a, b) => a + b, 0), y, { width: columnWidths[i], align: 'center' });
    });
    y += 20; 


    tableRows.forEach(row => {
      row.forEach((cell, i) => {
        doc.text(cell.toString(), columnWidths.slice(0, i).reduce((a, b) => a + b, 0), y, { width: columnWidths[i], align: 'center' });
      });
      y += 20; 
    });

    doc.end();

    stream.on('finish', () => {
      res.download(filePath, 'pacientes.pdf', (err) => {
        if (err) {
          console.error('Error al descargar el archivo:', err);
          res.status(500).send('Error al descargar el archivo.');
        } else {
          fs.unlinkSync(filePath);
        }
      });
    });
  });
});

app.get('/promedio-pacientes', requireLogin, requireRole(['médico','admin']), (req, res) => {
  const tipo_usuario = req.session.user;
  const navbarHtml = navbar(tipo_usuario);
  connection.query(`SELECT AVG(edad) AS edad, AVG(peso) AS peso, AVG(altura) AS altura, AVG(frecuencia_cardiaca) AS frecuencia_cardiaca FROM pacientes; `, (err, results) => {
    if (err) {
      let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
    </head>
    <body>
    <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
      <h1>Error al obtener los datos:(</h1> 
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
    `;
    return res.send(html);
    }
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente</title>
      </head>
      <body>
      <div id="navbar">
          ${navbarHtml}
        </div>
        <main>
        <table>
          <thead>
            <tr>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
              <th>Altura (m)</th>
              <th>Peso (kg)</th>
            </tr>
          </thead>
          <tbody>
    `;
    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
          <td>${paciente.altura}</td>
          <td>${paciente.peso}</td>
        </tr>
      `;
    });
    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/pacientes'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  });
});

app.get('/equipos-e-x', requireLogin, requireRole(['admin', 'médico']), (req, res) => {
  res.sendFile(__dirname + '/public/pacientes-x.html');
});

app.post('/upload-e-x', upload.single('excelFile'), requireRole(['admin', 'médico']), (req, res) => {
  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
  const tipo_usuario = req.session.user.tipo_usuario;
  const navbarHtml = navbar(tipo_usuario);

  if (!data || data.length === 0) {
      return res.status(400).send('El archivo Excel está vacío o no contiene datos válidos.');
  }

  connection.beginTransaction(err => {
      if (err) {
          console.error('Error al iniciar la transacción:', err);
          return res.status(500).send('Error al procesar la solicitud');
      }

      const values = data.map(row => [
          row.nombre_equipo, 
          row.estado, 
          row.descripcion, 
          row.ultimo_mantenimiento,  
          row.id_ma,
          row.id_hospital
      ]);

      const sql = `INSERT INTO equipos (nombre_equipo, estado, descripcion, ultimo_mantenimiento, id_ma, id_hospital) VALUES (?`;

      connection.query(sql, [values], err => {
          if (err) {
              return connection.rollback(() => {
                  console.error('Error en la consulta:', err);
                  return res.status(500).send('Error al cargar los datos desde el archivo Excel.');
              });
          }

          connection.commit(err => {
              if (err) {
                  return connection.rollback(() => {
                      console.error('Error al realizar el commit:', err);
                      return res.status(500).send('Error al procesar la solicitud');
                  });
              }

              let html = `
              <html>
              <head>
                  <link rel="stylesheet" href="/styles.css">
                  <title>Datos subidos</title>
              </head>
              <body>
                  <div id="navbar">${navbarHtml}</div>
                  <main>
                      <h1>Los datos se han subido con éxito al servidor</h1>
                      <button onclick="window.location.href='/pacientes-x'">Volver</button>
                  </main>
              </body>
              </html>
              `;
              return res.send(html);
          });
      });
  });
});

app.get('/download-e-x', requireRole(['admin', 'médico']), (req, res) => {
  const sql = `SELECT * FROM equipos`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'equipos');

    const filePath = path.join(__dirname, 'uploads', 'equipos.xlsx');
    xlsx.writeFile(workbook, filePath);
    return res.download(filePath, 'equipos.xlsx');
  });
});

app.get('/download-e-pdf', requireLogin, requireRole('médico'), (req, res) => {
  const sql = 'SELECT * FROM equipos';
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error al consultar la base de datos:", err);
      return res.status(500).send('Error al obtener los datos.');
    }

    const doc = new PDFDocument({ autoFirstPage: false }); 
    const filePath = path.join(__dirname, 'uploads', 'equipos.pdf');
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    doc.addPage();

    doc.fontSize(14).text('Equipos registrados', { align: 'center' }).moveDown();

    const tableHeaders = ['ID', 'Nombre', 'Estado', 'Descripcion', 'Ultimo Mantenmiento'];
    const tableRows = results.map((equipo) => [ 
          equipo.id,
          equipo.nombre_equipo,
          equipo.estado,
          equipo.descripcion,
          equipo.ultimo_mantenimiento
    ]);

    const columnWidths = [50, 100, 100, 50, 50, 50, 150];

    let y = doc.y; 
    tableHeaders.forEach((header, i) => {
      doc.text(header, columnWidths.slice(0, i).reduce((a, b) => a + b, 0), y, { width: columnWidths[i], align: 'center' });
    });
    y += 20; 


    tableRows.forEach(row => {
      row.forEach((cell, i) => {
        doc.text(cell.toString(), columnWidths.slice(0, i).reduce((a, b) => a + b, 0), y, { width: columnWidths[i], align: 'center' });
      });
      y += 20; 
    });

    doc.end();

    stream.on('finish', () => {
      res.download(filePath, 'equipos.pdf', (err) => {
        if (err) {
          console.error('Error al descargar el archivo:', err);
          res.status(500).send('Error al descargar el archivo.');
        } else {
          fs.unlinkSync(filePath);
        }
      });
    });
  });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}` );
  });
