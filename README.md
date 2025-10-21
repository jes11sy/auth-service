# Auth Service

Unified authentication microservice for CRM system.

## Auto Deploy

При пуше в `main` ветку:
1. Автоматически собирается Docker образ
2. Пушится на Docker Hub: `jes11sy/auth-service:latest`
3. Готов к деплою в Kubernetes

## Setup Secrets

В настройках GitHub репозитория добавь:
- `DOCKERHUB_USERNAME` - твой логин Docker Hub
- `DOCKERHUB_TOKEN` - Access Token из Docker Hub

## Local Development

```bash
npm install
npm run start:dev
```

## Deploy to Kubernetes

```bash
kubectl rollout restart deployment/auth-service -n backend
```
