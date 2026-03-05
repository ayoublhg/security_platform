.PHONY: help up down logs clean

help:
	@echo "Commandes disponibles:"
	@echo "  make up    - Démarrer tous les services"
	@echo "  make down  - Arrêter tous les services"
	@echo "  make logs  - Voir les logs"
	@echo "  make clean - Nettoyer les conteneurs"
	@echo "  make ps    - Voir l'état des services"

up:
	docker-compose up -d --build
	@echo "✅ Services démarrés"
	@echo "📊 Dashboard: http://localhost:5000"
	@echo "📚 API Docs: http://localhost:8080/docs"
	@echo "📈 Grafana: http://localhost:3000 (admin/admin)"
	@echo "🔍 Prometheus: http://localhost:9090"

down:
	docker-compose down
	@echo "✅ Services arrêtés"

logs:
	docker-compose logs -f

clean:
	docker-compose down -v
	docker system prune -f
	@echo "✅ Nettoyage effectué"

ps:
	docker-compose ps

restart:
	docker-compose restart