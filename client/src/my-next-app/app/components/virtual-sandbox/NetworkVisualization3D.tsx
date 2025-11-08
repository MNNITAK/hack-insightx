/*
Virtual Cybersecurity Sandbox - 3D Network Visualization
Real-time 3D visualization of network topology and attack propagation
*/

import React, { useRef, useEffect, useState } from 'react';
import * as THREE from 'three';

interface NetworkNode {
  id: string;
  name: string;
  type: string;
  status: string; // "healthy", "suspicious", "under_attack"
  ip_address: string;
  security_events: number;
  position: { x: number; y: number; z: number };
}

interface NetworkEdge {
  source: string;
  target: string;
  traffic_volume: number;
  connection_type: string;
  security_status: string;
}

interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

interface AttackIndicators {
  active_attacks: number;
  suspicious_nodes: number;
}

const NetworkVisualization3D: React.FC<{
  sandboxId: string;
  isVisible: boolean;
}> = ({ sandboxId, isVisible }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<THREE.Scene>();
  const rendererRef = useRef<THREE.WebGLRenderer>();
  const cameraRef = useRef<THREE.PerspectiveCamera>();
  const nodeObjectsRef = useRef<Map<string, THREE.Object3D>>(new Map());
  const edgeObjectsRef = useRef<Map<string, THREE.Line>>(new Map());
  
  const [networkData, setNetworkData] = useState<NetworkTopology>({ nodes: [], edges: [] });
  const [attackIndicators, setAttackIndicators] = useState<AttackIndicators>({ active_attacks: 0, suspicious_nodes: 0 });
  const [isLoading, setIsLoading] = useState(false);

  // Initialize 3D scene
  useEffect(() => {
    if (!mountRef.current || !isVisible) return;

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x1a1a1a);
    sceneRef.current = scene;

    // Camera setup
    const camera = new THREE.PerspectiveCamera(
      75,
      mountRef.current.clientWidth / mountRef.current.clientHeight,
      0.1,
      1000
    );
    camera.position.set(0, 50, 100);
    camera.lookAt(0, 0, 0);
    cameraRef.current = camera;

    // Renderer setup
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(mountRef.current.clientWidth, mountRef.current.clientHeight);
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    rendererRef.current = renderer;

    mountRef.current.appendChild(renderer.domElement);

    // Lighting
    const ambientLight = new THREE.AmbientLight(0x404040, 0.6);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(50, 50, 50);
    directionalLight.castShadow = true;
    scene.add(directionalLight);

    // Grid
    const gridHelper = new THREE.GridHelper(200, 20, 0x444444, 0x222222);
    scene.add(gridHelper);

    // Mouse controls (basic rotation)
    let mouseX = 0;
    let mouseY = 0;
    const onMouseMove = (event: MouseEvent) => {
      mouseX = (event.clientX / window.innerWidth) * 2 - 1;
      mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
    };
    
    window.addEventListener('mousemove', onMouseMove);

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);
      
      // Rotate camera based on mouse
      camera.position.x = Math.cos(mouseX * Math.PI) * 100;
      camera.position.z = Math.sin(mouseX * Math.PI) * 100;
      camera.position.y = 50 + mouseY * 50;
      camera.lookAt(0, 0, 0);
      
      renderer.render(scene, camera);
    };
    animate();

    // Cleanup
    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      if (mountRef.current && renderer.domElement) {
        mountRef.current.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [isVisible]);

  // Fetch network topology data
  const fetchNetworkData = async () => {
    if (!sandboxId) return;

    setIsLoading(true);
    try {
      const response = await fetch(`/api/sandbox/${sandboxId}/network-visualization`, {
        method: 'POST'
      });

      if (response.ok) {
        const data = await response.json();
        setNetworkData(data.topology);
        setAttackIndicators(data.attack_indicators);
        updateVisualization(data.topology);
      }
    } catch (error) {
      console.error('Failed to fetch network data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Update 3D visualization with new data
  const updateVisualization = (topology: NetworkTopology) => {
    if (!sceneRef.current) return;

    const scene = sceneRef.current;

    // Clear existing objects
    nodeObjectsRef.current.forEach(obj => scene.remove(obj));
    edgeObjectsRef.current.forEach(obj => scene.remove(obj));
    nodeObjectsRef.current.clear();
    edgeObjectsRef.current.clear();

    // Create node objects
    topology.nodes.forEach((node, index) => {
      const nodeGroup = new THREE.Group();

      // Node geometry based on type
      let geometry: THREE.BufferGeometry;
      let material: THREE.Material;

      switch (node.type) {
        case 'web_server':
          geometry = new THREE.BoxGeometry(8, 8, 8);
          material = new THREE.MeshLambertMaterial({ color: getNodeColor(node.status) });
          break;
        case 'database':
          geometry = new THREE.CylinderGeometry(4, 4, 8);
          material = new THREE.MeshLambertMaterial({ color: getNodeColor(node.status) });
          break;
        case 'firewall':
          geometry = new THREE.OctahedronGeometry(5);
          material = new THREE.MeshLambertMaterial({ color: getNodeColor(node.status) });
          break;
        case 'user_device':
          geometry = new THREE.SphereGeometry(4);
          material = new THREE.MeshLambertMaterial({ color: getNodeColor(node.status) });
          break;
        default:
          geometry = new THREE.BoxGeometry(6, 6, 6);
          material = new THREE.MeshLambertMaterial({ color: getNodeColor(node.status) });
      }

      const mesh = new THREE.Mesh(geometry, material);
      mesh.castShadow = true;
      mesh.receiveShadow = true;

      // Position nodes in a circle if no position specified
      if (node.position.x === 0 && node.position.y === 0 && node.position.z === 0) {
        const angle = (index / topology.nodes.length) * Math.PI * 2;
        const radius = 50;
        node.position.x = Math.cos(angle) * radius;
        node.position.z = Math.sin(angle) * radius;
        node.position.y = 0;
      }

      mesh.position.set(node.position.x, node.position.y, node.position.z);
      nodeGroup.add(mesh);

      // Add status indicator
      if (node.status === 'under_attack') {
        const warningGeometry = new THREE.ConeGeometry(2, 6, 8);
        const warningMaterial = new THREE.MeshLambertMaterial({ color: 0xff0000 });
        const warning = new THREE.Mesh(warningGeometry, warningMaterial);
        warning.position.y = 12;
        nodeGroup.add(warning);

        // Pulsing animation for attacked nodes
        const pulseScale = Math.sin(Date.now() * 0.005) * 0.2 + 1;
        mesh.scale.setScalar(pulseScale);
      }

      // Add label
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      if (context) {
        canvas.width = 256;
        canvas.height = 64;
        context.fillStyle = '#ffffff';
        context.font = '16px Arial';
        context.textAlign = 'center';
        context.fillText(node.name, 128, 32);

        const texture = new THREE.CanvasTexture(canvas);
        const labelMaterial = new THREE.SpriteMaterial({ map: texture });
        const label = new THREE.Sprite(labelMaterial);
        label.position.y = 15;
        label.scale.set(20, 5, 1);
        nodeGroup.add(label);
      }

      nodeGroup.position.copy(mesh.position);
      scene.add(nodeGroup);
      nodeObjectsRef.current.set(node.id, nodeGroup);
    });

    // Create edge objects (connections)
    topology.edges.forEach(edge => {
      const sourceNode = topology.nodes.find(n => n.id === edge.source);
      const targetNode = topology.nodes.find(n => n.id === edge.target);

      if (sourceNode && targetNode) {
        const points = [
          new THREE.Vector3(sourceNode.position.x, sourceNode.position.y, sourceNode.position.z),
          new THREE.Vector3(targetNode.position.x, targetNode.position.y, targetNode.position.z)
        ];

        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const material = new THREE.LineBasicMaterial({ 
          color: getEdgeColor(edge.security_status),
          linewidth: Math.max(1, edge.traffic_volume / 1000)
        });

        const line = new THREE.Line(geometry, material);
        scene.add(line);
        edgeObjectsRef.current.set(`${edge.source}-${edge.target}`, line);
      }
    });
  };

  // Get node color based on status
  const getNodeColor = (status: string): number => {
    switch (status) {
      case 'healthy': return 0x00ff00;
      case 'suspicious': return 0xffaa00;
      case 'under_attack': return 0xff0000;
      default: return 0x666666;
    }
  };

  // Get edge color based on security status
  const getEdgeColor = (status: string): number => {
    switch (status) {
      case 'normal': return 0x00aaff;
      case 'suspicious': return 0xffaa00;
      case 'malicious': return 0xff0000;
      default: return 0x666666;
    }
  };

  // Fetch data on mount and set up polling
  useEffect(() => {
    if (isVisible && sandboxId) {
      fetchNetworkData();
      
      // Poll for updates every 5 seconds
      const interval = setInterval(fetchNetworkData, 5000);
      return () => clearInterval(interval);
    }
  }, [isVisible, sandboxId]);

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      if (mountRef.current && cameraRef.current && rendererRef.current) {
        const width = mountRef.current.clientWidth;
        const height = mountRef.current.clientHeight;

        cameraRef.current.aspect = width / height;
        cameraRef.current.updateProjectionMatrix();
        rendererRef.current.setSize(width, height);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  if (!isVisible) return null;

  return (
    <div className="relative w-full h-full bg-gray-900">
      <div ref={mountRef} className="w-full h-full" />
      
      {/* Overlay controls and info */}
      <div className="absolute top-4 left-4 bg-black bg-opacity-70 text-white p-4 rounded space-y-2">
        <div className="text-lg font-bold">🌐 Network Topology</div>
        <div className="text-sm space-y-1">
          <div>Nodes: {networkData.nodes.length}</div>
          <div>Connections: {networkData.edges.length}</div>
          <div className="text-red-400">⚠️ Active Attacks: {attackIndicators.active_attacks}</div>
          <div className="text-yellow-400">🔍 Suspicious: {attackIndicators.suspicious_nodes}</div>
        </div>
        
        <button
          onClick={fetchNetworkData}
          disabled={isLoading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm disabled:opacity-50"
        >
          {isLoading ? '🔄 Updating...' : '🔄 Refresh'}
        </button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-black bg-opacity-70 text-white p-4 rounded space-y-2">
        <div className="text-lg font-bold">Legend</div>
        <div className="text-sm space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded"></div>
            <span>Healthy</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded"></div>
            <span>Suspicious</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded"></div>
            <span>Under Attack</span>
          </div>
        </div>
        
        <div className="text-xs text-gray-400 mt-2">
          Mouse: Rotate view<br/>
          Auto-refresh: 5s
        </div>
      </div>
    </div>
  );
};

export default NetworkVisualization3D;