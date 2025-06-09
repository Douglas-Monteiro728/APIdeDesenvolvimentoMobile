import express from 'express';
import pkg from '@prisma/client';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import morgan from 'morgan';

dotenv.config();

const { PrismaClient } = pkg;
const prisma = new PrismaClient();

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

const JWT_SECRET = process.env.JWT_SECRET || 'token123';

// Middleware de autenticação via JWT
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Configuração do multer para upload local
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

// Filtra arquivos de imagem e vídeo para upload
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/x-matroska'
  ];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de arquivo não permitido. Apenas imagens e vídeos são aceitos.'));
  }
};

const upload = multer({ storage, fileFilter });

// Criar pasta uploads se não existir
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Servir arquivos estáticos da pasta uploads
app.use('/uploads', express.static('uploads'));

// ---------- ROTAS ----------

// Criar novo post com múltiplas mídias (imagens e vídeos)
app.post('/posts', autenticarToken, upload.array('midias', 10), async (req, res) => {
    try {
      const { texto, categoriaId } = req.body;
  
      console.log('--- Início do POST /posts ---');
      console.log('Recebido texto:', texto);
      console.log('Recebido categoriaId:', categoriaId);
      console.log('Tipo de categoriaId:', typeof categoriaId);
      console.log('Arquivos recebidos:', req.files);
  
      if (!texto || !categoriaId) {
        console.log('Erro: texto ou categoriaId não fornecidos');
        return res.status(400).json({ error: 'Texto e categoria são obrigatórios.' });
      }
  
      const userId = req.user.id;
  
      // Verificar se categoria existe
        const categoriaNome = categoriaId.trim();
        const categoriaExistente = await prisma.categoria.findFirst({
            where: { nome: categoriaId }
        });
        
        const todasCategorias = await prisma.categoria.findMany();
        console.log('Categorias no banco:', todasCategorias.map(c => c.nome));


        if (!categoriaExistente) {
            console.log('Categoria não encontrada:', categoriaNome);
            return res.status(400).json({ error: `Categoria inválida: ${categoriaNome}` });
        }
        
        const novoPost = await prisma.post.create({
            data: {
            texto,
            categoriaId: categoriaExistente.id,
            userId,
            },
        });
  
  
      // Criar registros de mídias relacionadas, se houver arquivos enviados
      if (req.files && req.files.length > 0) {
        const midiasData = req.files.map(file => ({
          url: `http://192.168.1.2:3000/uploads/${file.filename}`,
          tipo: file.mimetype.startsWith('video/') ? 'video' : 'imagem',
          postId: novoPost.id,
        }));
  
        console.log('Criando registros de mídias:', midiasData);
  
        await prisma.midia.createMany({
          data: midiasData,
        });
      }
  
      // Buscar post criado com as mídias e dados relacionados
      const postComMidias = await prisma.post.findUnique({
        where: { id: novoPost.id },
        include: {
          user: { select: { id: true, name: true, avatarUrl: true } },
          categoria: true,
          midias: true,
        },
      });
  
      console.log('Post criado com sucesso:', postComMidias);
  
      res.status(201).json({
        id: postComMidias.id,
        texto: postComMidias.texto,
        categoria: postComMidias.categoria.nome,
        midias: postComMidias.midias.map(m => ({ url: m.url, tipo: m.tipo })),
        nome: postComMidias.user.name,
        avatar: postComMidias.user.avatarUrl,
        tempo: postComMidias.createdAt,
      });
  
    } catch (error) {
      console.error('Erro ao criar post:', error);
      res.status(500).json({ error: 'Erro interno ao criar post.' });
    }
  });
  

// Listar posts (com dados do usuário e mídias)
app.get('/posts', async (req, res) => {
    try {
      const { categoria } = req.query;
  
      const filtroCategoria = categoria
        ? { categoria: { nome: categoria } }
        : {};
  
      const posts = await prisma.post.findMany({
        where: filtroCategoria,
        orderBy: { createdAt: 'desc' },
        include: {
          user: { select: { id: true, name: true, avatarUrl: true } },
          categoria: true,
          midias: true,
        },
      });
  
      const formattedPosts = posts.map(post => ({
        id: post.id,
        texto: post.texto,
        categoria: post.categoria?.nome || null,
        midias: post.midias.map(m => ({ url: m.url, tipo: m.tipo })),
        nome: post.user.name,
        avatar: post.user.avatarUrl,
        tempo: post.createdAt,
      }));
  
      res.json(formattedPosts);
    } catch (error) {
      console.error('Erro ao buscar posts:', error);
      res.status(500).json({ error: 'Erro interno no servidor.' });
    }
  });
  

// Login de usuário
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado.' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) {
      return res.status(401).json({ error: 'Senha incorreta.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Login efetuado com sucesso!',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatarUrl: user.avatarUrl || null,
      },
      token,
    });
  } catch (error) {
    console.error('Erro no login:', error.message);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Cadastro de usuário
app.post('/usuarios', async (req, res) => {
  try {
    const senhaHash = await bcrypt.hash(req.body.senha, 10);
    const newUser = await prisma.user.create({
      data: {
        email: req.body.email,
        name: req.body.name,
        senha: senhaHash,
      },
    });

    res.status(201).json({
      email: newUser.email,
      name: newUser.name,
      id: newUser.id,
    });
  } catch (error) {
    console.error('Erro ao criar usuário:', error.message);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Listar usuários
app.get('/usuarios', async (req, res) => {
  try {
    let users = {};

    if (req.query.name || req.query.email) {
      users = await prisma.user.findMany({
        where: {
          name: req.query.name,
          email: req.query.email,
        },
      });
    } else {
      users = await prisma.user.findMany();
    }

    res.status(200).json(users);
  } catch (error) {
    console.error('Erro ao listar usuários:', error.message);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Atualizar usuário com upload de avatar
app.put('/usuarios/:id', upload.single('avatar'), async (req, res) => {
  const userId = req.params.id;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'ID do usuário inválido.' });
  }

  const { name, email, removeAvatar } = req.body;

  try {
    const userAtual = await prisma.user.findUnique({ where: { id: userId } });
    if (!userAtual) return res.status(404).json({ error: 'Usuário não encontrado.' });

    let avatarUrl = userAtual.avatarUrl;

    if (req.file) {
      avatarUrl = `http://192.168.1.2:3000/uploads/${req.file.filename}`;
    } else if (removeAvatar === 'true') {
      avatarUrl = null;
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        name,
        email,
        avatarUrl,
      },
    });

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error('Erro ao atualizar usuário:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

app.get('/categorias', async (req, res) => {
  try {
    const categorias = await prisma.categoria.findMany();
    res.json(categorias);
  } catch (error) {
    console.error('Erro ao buscar categorias:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Deletar usuário
app.delete('/usuarios/:id', async (req, res) => {
  const id = req.params.id;

  if (!id) {
    return res.status(400).json({ error: 'ID do usuário é obrigatório.' });
  }

  try {
    await prisma.user.delete({
      where: { id },
    });

    res.status(200).json({ message: 'Usuário deletado com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar usuário:', error.message);
    res.status(500).json({ error: 'Erro ao deletar usuário.' });
  }
});

// Função para popular categorias iniciais
async function criarCategoriasIniciais() {
    const categorias = ['Popular', 'Comida', 'Fotografia', 'Música', 'Arte', 'Filmes', 'Jogos', 'Viagens'];
  
    for (const nome of categorias) {
      // Verifica se já existe
      const existe = await prisma.categoria.findUnique({ where: { nome } });
      if (!existe) {
        await prisma.categoria.create({ data: { nome } });
        console.log(`Categoria criada: ${nome}`);
      }
    }
  }
  
  // Chama a função para criar categorias quando a API iniciar
  criarCategoriasIniciais()
    .then(() => {
      console.log('Categorias iniciais configuradas.');
      app.listen(3000, '0.0.0.0', () => console.log('API rodando em todas as interfaces (0.0.0.0)'));
    })
    .catch(err => {
      console.error('Erro ao criar categorias iniciais:', err);
      process.exit(1); // sai com erro se não conseguir criar categorias
    });
  