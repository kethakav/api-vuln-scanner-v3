"""
OWASP ZAP API Testing Backend
FastAPI application for managing ZAP instances and running security scans
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import docker
import uuid
import secrets
from datetime import datetime
import asyncio
from contextlib import asynccontextmanager
import logging
from zapv2 import ZAPv2
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MAX_ZAP_INSTANCES = 10
ZAP_MEMORY_LIMIT = "2g"
ZAP_CPU_LIMIT = 1.0
ZAP_BASE_PORT = 8090
ZAP_IMAGE = "zaproxy/zap-stable:latest"
SHARED_HOST_DIR = os.path.abspath(os.path.join(os.getcwd(), "temp"))
SHARED_CONTAINER_DIR = "/zap/wrk"

# Global state management
zap_instances: Dict[str, Dict[str, Any]] = {}
docker_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app"""
    global docker_client
    try:
        # Ensure shared host directory exists (used to mount into ZAP containers)
        os.makedirs(SHARED_HOST_DIR, exist_ok=True)

        docker_client = docker.from_env()
        # Pull ZAP image on startup
        logger.info(f"Pulling ZAP Docker image: {ZAP_IMAGE}")
        docker_client.images.pull(ZAP_IMAGE)
        logger.info("ZAP image pulled successfully")
        logger.info(
            "Shared volume prepared: host '%s' -> container '%s'",
            SHARED_HOST_DIR,
            SHARED_CONTAINER_DIR,
        )
        yield
    finally:
        # Cleanup on shutdown
        cleanup_all_instances()
        if docker_client:
            docker_client.close()


app = FastAPI(
    title="ZAP API Testing Platform",
    description="Backend for OWASP ZAP API testing with Docker container management",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic Models
class ZAPInstanceResponse(BaseModel):
    instance_id: str
    port: int
    api_key: str
    status: str
    created_at: str


class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = Field(..., description="active or passive")
    context_name: Optional[str] = None


class SpiderRequest(BaseModel):
    target_url: str
    max_children: Optional[int] = None
    recurse: Optional[bool] = True
    context_name: Optional[str] = None

class OpenAPIImportRequest(BaseModel):
    target: Optional[str] = None
    context_name: Optional[str] = None

class ContextRequest(BaseModel):
    context_name: str
    include_regex: List[str] = []
    exclude_regex: List[str] = []


class ScanPolicyRequest(BaseModel):
    policy_name: str
    scan_ids: List[int] = []

class UpdateUrlsRequest(BaseModel):
    context_name: str
    all_urls: List[str] = []
    include_urls: List[str] = []

class AlertsResponse(BaseModel):
    alerts: List[Dict[str, Any]]
    count: int


# Helper Functions ===================================================================================================
def cleanup_all_instances():
    """Clean up all ZAP instances on shutdown"""
    global zap_instances, docker_client
    for instance_id, instance_data in list(zap_instances.items()):
        try:
            container = docker_client.containers.get(instance_data["container_id"])
            container.stop(timeout=10)
            container.remove()
            logger.info(f"Cleaned up instance: {instance_id}")
        except Exception as e:
            logger.error(f"Error cleaning up instance {instance_id}: {e}")
    zap_instances.clear()


def get_available_port() -> int:
    """Find an available port for ZAP instance"""
    used_ports = {data["port"] for data in zap_instances.values()}
    for port in range(ZAP_BASE_PORT, ZAP_BASE_PORT + 1000):
        if port not in used_ports:
            return port
    raise HTTPException(status_code=500, detail="No available ports")


async def create_zap_container(port: int, api_key: str) -> str:
    """Create and start a ZAP Docker container"""
    global docker_client
    
    container_name = f"zap_{uuid.uuid4().hex[:8]}"
    
    try:
        container = docker_client.containers.run(
            ZAP_IMAGE,
            name=container_name,
            detach=True,
            ports={f"{port}/tcp": port},
            mem_limit=ZAP_MEMORY_LIMIT,
            cpu_quota=int(ZAP_CPU_LIMIT * 100000),
            cpu_period=100000,
            volumes={
                # Mount host temp directory into the container so ZAP can access uploaded files
                "zapwork": {"bind": SHARED_CONTAINER_DIR, "mode": "rw"}
            },
            command=[
                "zap.sh",
                "-daemon",
                "-host", "0.0.0.0",
                "-port", str(port),
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", f"api.key={api_key}",
                "-config", "api.disablekey=false",
                "-config", "start.checkForUpdates=false",
                "-config", "start.checkAddonUpdates=false"
            ],
            remove=False,
        )
        # readiness wait to avoid racing ZAP startup.
        # Wait for container to be ready
        for _ in range(30):
            container.reload()
            if container.status == "running":
                break
            await asyncio.sleep(1)
        return container.id
    except Exception as e:
        logger.error(f"Error creating ZAP container: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create ZAP container: {str(e)}")


def get_zap_client(instance_id: str) -> ZAPv2:
    """Get ZAP API client for an instance"""
    if instance_id not in zap_instances:
        raise HTTPException(status_code=404, detail="ZAP instance not found")
    
    instance = zap_instances[instance_id]
    return ZAPv2(
        apikey=instance["api_key"],
        proxies={
            "http": f"http://host.docker.internal:{instance['port']}",
            "https": f"http://host.docker.internal:{instance['port']}"
        }
    )

# API Endpoints ===================================================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "active_instances": len(zap_instances),
        "max_instances": MAX_ZAP_INSTANCES
    }


@app.post("/instances", response_model=ZAPInstanceResponse)
async def create_instance():
    """Create a new ZAP instance"""
    if len(zap_instances) >= MAX_ZAP_INSTANCES:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum number of instances ({MAX_ZAP_INSTANCES}) reached"
        )
    
    instance_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    port = get_available_port()
    
    try:
        container_id = await create_zap_container(port, api_key)
        
        zap_instances[instance_id] = {
            "container_id": container_id,
            "port": port,
            "api_key": api_key,
            "status": "running",
            "created_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Created ZAP instance: {instance_id} on port {port}")
        
        return ZAPInstanceResponse(
            instance_id=instance_id,
            port=port,
            api_key=api_key,
            status="running",
            created_at=zap_instances[instance_id]["created_at"]
        )
    except Exception as e:
        logger.error(f"Failed to create instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances")
async def list_instances():
    """List all active ZAP instances"""
    return {
        "instances": [
            {
                "instance_id": iid,
                "port": data["port"],
                "status": data["status"],
                "created_at": data["created_at"]
            }
            for iid, data in zap_instances.items()
        ],
        "count": len(zap_instances)
    }


@app.delete("/instances/{instance_id}")
async def delete_instance(instance_id: str):
    """Delete a ZAP instance"""
    if instance_id not in zap_instances:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    try:
        instance = zap_instances[instance_id]
        container = docker_client.containers.get(instance["container_id"])
        container.stop(timeout=10)
        container.remove()
        
        del zap_instances[instance_id]
        logger.info(f"Deleted instance: {instance_id}")
        
        return {"message": "Instance deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting instance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/openapi")
async def import_openapi(
    instance_id: str, 
    target: Optional[str] = Form(None),
    context_name: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    """Import OpenAPI specification"""
    zap = get_zap_client(instance_id)
    
    try:
        content = await file.read()

        # Normalize extension and create a safe filename
        original_ext = (Path(file.filename).suffix or ".json").lower()
        if original_ext not in (".json", ".yaml", ".yml"):
            # Default to .json if unknown
            original_ext = ".json"

        unique_name = f"openapi_{uuid.uuid4().hex}{original_ext}"
        container_file_path = f"{SHARED_CONTAINER_DIR}/{unique_name}"

        # Save to the shared host directory (mounted into container)
        with open(container_file_path, "wb") as f:
            f.write(content)

        logger.info(
            "Saved OpenAPI to shared volume: '%s'",
            container_file_path,
        )

        if target:
            result = zap.openapi.import_file(container_file_path, target=target)
        else:
            # Import OpenAPI spec from the in-container path
            result = zap.openapi.import_file(container_file_path)

        if context_name:
            # Add all imported URLs to the specified context
            urls = zap.core.urls()
            for url in urls:
                zap.context.include_in_context(context_name, url)

        return {
            "message": "OpenAPI spec imported successfully",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error importing OpenAPI: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/context")
async def create_context(instance_id: str, request: ContextRequest):
    """Create a new context"""
    zap = get_zap_client(instance_id)
    
    try:
        # Create context
        context_id = zap.context.new_context(request.context_name)
        
        # Add include URLs
        for regex in request.include_regex:
            zap.context.include_in_context(request.context_name, regex)
        
        # Add exclude URLs
        for regex in request.exclude_regex:
            zap.context.exclude_from_context(request.context_name, regex)
        
        return {
            "context_id": context_id,
            "context_name": request.context_name,
            "message": "Context created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/contexts")
async def list_contexts(instance_id: str):
    """List all contexts"""
    zap = get_zap_client(instance_id)
    
    try:
        contexts = zap.context.context_list
        return {"contexts": contexts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/instances/{instance_id}/update-urls")
async def update_urls(instance_id: str, request: UpdateUrlsRequest):
    """Update context URLs"""
    zap = get_zap_client(instance_id)

    try:
        # First, remove all URLs from the context
        for url in request.all_urls:
            zap.context.exclude_from_context(request.context_name, url)

        # Then, include only the specified URLs
        for url in request.include_urls:
            zap.context.include_in_context(request.context_name, url)

        return {
            "context_name": request.context_name,
            "included_urls": request.include_urls,
            "message": "Context URLs updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating context URLs: {e}")
        raise HTTPException(status_code=500, detail=str(e))    


@app.post("/instances/{instance_id}/spider")
async def start_spider(instance_id: str, request: SpiderRequest):
    """Start spider scan"""
    zap = get_zap_client(instance_id)
    
    try:
        # Start spider
        scan_id = zap.spider.scan(
            url=request.target_url,
            maxchildren=request.max_children,
            recurse=request.recurse,
            # contextname=request.context_name
        )

        return {
            "scan_id": scan_id,
            "message": "Spider started successfully"
        }
    except Exception as e:
        logger.error(f"Error starting spider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/spider/{scan_id}/status")
async def spider_status(instance_id: str, scan_id: str):
    """Get spider scan status"""
    zap = get_zap_client(instance_id)
    
    try:
        status = zap.spider.status(scan_id)
        return {
            "scan_id": scan_id,
            "status": status,
            "progress": f"{status}%"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/spider/{scan_id}/results")
async def spider_results(instance_id: str, scan_id: str, context_name: Optional[str] = None):
    """Get spider scan results"""
    zap = get_zap_client(instance_id)
    logger.info(f"Fetching spider results for scan ID: {scan_id} with context: {context_name}")
    
    try:
        results = zap.spider.results(scan_id)
        if context_name:
            logger.info(f"Filtering spider results by context: {context_name}")
            context_urls = []
            for url in results:
                zap.context.include_in_context(context_name, url)   
                context_urls.append(url)
            results = context_urls

        context = zap.context.context(context_name) if context_name else None
        logger.info(context)
        return {
            "scan_id": scan_id,
            "urls": results,
            "count": len(results)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/scan/active")
async def start_active_scan(instance_id: str, request: ScanRequest):
    """Start active scan"""
    zap = get_zap_client(instance_id)
    logger.info(f"Starting {request.scan_type} scan on {request.target_url}")
    if request.scan_type.lower() == "active":
        try:
            zap.core.delete_all_alerts()
            if request.context_name:
                context_id = zap.context.context(request.context_name).get("id")
                logger.info(f"Using context '{request.context_name}' with ID {context_id} for active scan")
                scan_id = zap.ascan.scan(
                    url=request.target_url,
                    contextid=context_id if request.context_name else None
                )
            else:
                scan_id = zap.ascan.scan(url=request.target_url)
            
            return {
                "scan_id": scan_id,
                "scan_type": "active",
                "message": "Active scan started successfully"
            }
        except Exception as e:
            logger.error(f"Error starting active scan: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    else:
        # Run passive scan
        try:
            zap.pscan.enable_all_scanners()
            return {"message": "Passive scanning enabled"}
        except Exception as e:
            logger.error(f"Error enabling passive scan: {e}")
            raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/scan/active/{scan_id}/status")
async def active_scan_status(instance_id: str, scan_id: str):
    """Get active scan status"""
    zap = get_zap_client(instance_id)
    
    try:
        status = zap.ascan.status(scan_id)
        return {
            "scan_id": scan_id,
            "status": status,
            "progress": f"{status}%"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/scan/policies")
async def get_scan_policies(instance_id: str):
    """Get available scan policies"""
    zap = get_zap_client(instance_id)
    
    try:
        policies = zap.ascan.scan_policy_names
        return {"policies": policies}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/scan/scanners")
async def get_scanners(instance_id: str):
    """Get available scanners"""
    zap = get_zap_client(instance_id)
    
    try:
        scanners = zap.ascan.scanners()
        return {"scanners": scanners}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/scan/scanners/{scanner_id}/enable")
async def enable_scanner(instance_id: str, scanner_id: int):
    """Enable a specific scanner"""
    zap = get_zap_client(instance_id)
    
    try:
        zap.ascan.enable_scanners(ids=str(scanner_id))
        return {"message": f"Scanner {scanner_id} enabled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/scan/scanners/{scanner_id}/disable")
async def disable_scanner(instance_id: str, scanner_id: int):
    """Disable a specific scanner"""
    zap = get_zap_client(instance_id)
    
    try:
        zap.ascan.disable_scanners(ids=str(scanner_id))
        return {"message": f"Scanner {scanner_id} disabled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/alerts", response_model=AlertsResponse)
async def get_alerts(
    instance_id: str,
    baseurl: Optional[str] = None,
    start: int = 0,
    count: int = 100
):
    """Get alerts from ZAP"""
    zap = get_zap_client(instance_id)
    
    try:
        alerts = zap.core.alerts(baseurl=baseurl, start=start, count=count)
        return AlertsResponse(
            alerts=alerts,
            count=len(alerts)
        )
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/alerts/summary")
async def get_alerts_summary(instance_id: str):
    """Get alerts summary by risk level"""
    zap = get_zap_client(instance_id)
    
    try:
        alerts = zap.core.alerts()
        summary = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for alert in alerts:
            risk = alert.get("risk", "").lower()
            if risk == "high":
                summary["high"] += 1
            elif risk == "medium":
                summary["medium"] += 1
            elif risk == "low":
                summary["low"] += 1
            else:
                summary["informational"] += 1
        
        return {
            "summary": summary,
            "total": len(alerts)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/urls")
async def get_urls(instance_id: str):
    """Get all URLs discovered by ZAP"""
    zap = get_zap_client(instance_id)
    
    try:
        urls = zap.core.urls()
        return {
            "urls": urls,
            "count": len(urls)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/instances/{instance_id}/passive-scan/enable")
async def enable_passive_scan(instance_id: str):
    """Enable passive scanning"""
    zap = get_zap_client(instance_id)
    
    try:
        zap.pscan.enable_all_scanners()
        return {"message": "Passive scanning enabled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/instances/{instance_id}/passive-scan/records")
async def get_passive_scan_records(instance_id: str):
    """Get passive scan records"""
    zap = get_zap_client(instance_id)
    
    try:
        records = zap.pscan.records_to_scan
        return {
            "records_to_scan": records,
            "message": f"{records} records pending"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
