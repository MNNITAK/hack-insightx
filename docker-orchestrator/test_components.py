#!/usr/bin/env python3
"""
🧪 Simple Docker Test
Test individual components without full orchestration
"""

import docker
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_web_server():
    """Test the web server component"""
    client = docker.from_env()
    
    try:
        # Build the web server image
        logger.info("🔨 Building web server image...")
        image_result = client.images.build(
            path="../docker-components/web_server",
            tag="insightx/test-nginx",
            rm=True
        )
        
        # Handle build result (returns tuple of (image, build_logs))
        if isinstance(image_result, tuple):
            image = image_result[0]
            build_logs = image_result[1]
        else:
            image = image_result
        
        logger.info(f"✅ Built image: {image.id[:12]}")
        
        # Run the container
        logger.info("🚀 Starting web server container...")
        container = client.containers.run(
            "insightx/test-nginx",
            name="test_web_server",
            ports={'80/tcp': 8080},
            detach=True,
            remove=True  # Auto-remove when stopped
        )
        
        # Wait a moment for startup
        time.sleep(3)
        
        # Check container status
        container.reload()
        logger.info(f"📊 Container status: {container.status}")
        
        if container.status == 'running':
            logger.info("✅ Web server is running!")
            logger.info("🌐 Access at: http://localhost:8080")
            
            # Show container logs
            logs = container.logs().decode('utf-8')
            if logs:
                logger.info(f"📋 Container logs:\n{logs}")
            
            # Keep running for a bit
            logger.info("⏰ Keeping container running for 10 seconds...")
            time.sleep(10)
            
        else:
            # Container failed
            logs = container.logs().decode('utf-8')
            logger.error(f"❌ Container failed. Status: {container.status}")
            logger.error(f"📋 Logs:\n{logs}")
        
        # Stop container
        logger.info("🛑 Stopping container...")
        container.stop()
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        
        # Cleanup on error
        try:
            existing = client.containers.get("test_web_server")
            existing.remove(force=True)
        except:
            pass

def test_database():
    """Test the database component"""
    client = docker.from_env()
    
    try:
        logger.info("🔨 Building database image...")
        image_result = client.images.build(
            path="../docker-components/database_server",
            tag="insightx/test-mysql",
            rm=True
        )
        
        # Handle build result
        if isinstance(image_result, tuple):
            image = image_result[0]
        else:
            image = image_result
            
        logger.info(f"✅ Built image: {image.id[:12]}")
        
        # Run the container
        logger.info("🚀 Starting database container...")
        container = client.containers.run(
            "insightx/test-mysql",
            name="test_database",
            environment={
                'MYSQL_ROOT_PASSWORD': 'admin123',
                'MYSQL_DATABASE': 'testdb'
            },
            ports={'3306/tcp': 3307},
            detach=True,
            remove=True
        )
        
        # Wait for database startup (MySQL needs more time)
        logger.info("⏰ Waiting for database initialization...")
        for i in range(30):
            container.reload()
            if container.status != 'running':
                break
                
            logs = container.logs().decode('utf-8')
            if "ready for connections" in logs:
                logger.info("✅ Database is ready!")
                break
                
            time.sleep(2)
        
        container.reload()
        if container.status == 'running':
            logger.info("✅ Database container is running!")
            logger.info("🗄️ Access at: localhost:3307")
        else:
            logs = container.logs().decode('utf-8')
            logger.error(f"❌ Database failed. Status: {container.status}")
            logger.error(f"📋 Logs:\n{logs[-1000:]}")  # Last 1000 chars
        
        # Stop container
        logger.info("🛑 Stopping database...")
        container.stop()
        
    except Exception as e:
        logger.error(f"❌ Database test failed: {e}")
        
        # Cleanup
        try:
            existing = client.containers.get("test_database")
            existing.remove(force=True)
        except:
            pass

if __name__ == "__main__":
    logger.info("🧪 Starting Docker component tests...")
    
    # Test web server
    logger.info("\n" + "="*50)
    logger.info("🌐 Testing Web Server Component")
    logger.info("="*50)
    test_web_server()
    
    # Test database
    logger.info("\n" + "="*50)
    logger.info("🗄️ Testing Database Component")  
    logger.info("="*50)
    test_database()
    
    logger.info("\n✅ Component tests completed!")