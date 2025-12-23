# ![API](https://img.shields.io/badge/API-FastAPI-blue) API de Tarefas

Uma **API RESTful** desenvolvida com **FastAPI**, **Python** e **SQLAlchemy** para gerenciar tarefas.  
Permite **cadastrar, listar, concluir e excluir tarefas** em um banco SQLite.  

O projeto utiliza **Docker** para garantir que a aplicação rode de forma consistente em qualquer ambiente.

---

## 🐳 Rodando a aplicação com Docker

### Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/)  
- [Docker Compose](https://docs.docker.com/compose/install/)  

### Passos

1. Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:

```env
DATABASE_URL = sqlite:///./Tarefas.db
meu_usuario = admin
minha_senha = admin
```
- A aplicação ficará disponível em http://localhost:8000
- Documentação interativa do FastAPI: http://localhost:8000/docs

2. Build do container:

```cmd
docker compose build
```

3. Rodar a aplicação:

```cmd
docker compose up
```

## 📝 Funcionalidades

### Cadastrar uma nova tarefa
- Evita cadastros duplicados
- Validações básicas com Pydantic

### Listar tarefas com paginação
- Suporte a page e limit
- Permite ordenar resultados por id ou nome
- Retorna também o total de tarefas cadastradas

### Excluir uma tarefa
- Exclusão pelo nome da tarefa
- Verificação de existência antes de remover

### Concluir tarefa
- Atualiza o campo concluida para true
- Apenas se a tarefa existir

### Autenticação via HTTP Basic
- Todas as rotas são protegidas
- Credenciais padrão: admin / admin

## 🚀 Tecnologias

- Python 3.13

- FastAPI

- SQLAlchemy

- Pydantic

- SQLite

- HTTP Basic Auth

- Uvicorn

- Docker + Docker Compose





