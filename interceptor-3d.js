/**
 * Guardrail Lab — 3D Quantum Defensive Interceptor (Studio Light Engine)
 * 
 * Physical Security Pipeline Visualization:
 * [AI Agent Node (Left)] ---> [Quantum Guardrail Shield (Center)] ---> [Protected Server (Right)]
 * 
 * - When BLOCKED: Projectile strikes the shield, shatters into emerald sparks & deflects backwards.
 * - When BYPASSED: Projectile breaches the porous shield, strikes the Server Core with crimson alarm sparks.
 * - High-end light studio aesthetics: crisp shadows, gemstone translucency, transparent background.
 */

export class QuantumInterceptor3D {
  constructor(canvasContainerId, onLayerSelect) {
    this.container = document.getElementById(canvasContainerId);
    this.onLayerSelect = onLayerSelect;
    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.shieldGroup = null;
    this.agentGroup = null;
    this.serverGroup = null;
    this.pipelineGroup = null;
    this.shieldMesh = null;
    this.shieldRings = [];
    this.particles = [];
    this.projectiles = [];
    this.ambientParticles = null;
    this.animationFrameId = null;
    this.raycaster = null;
    this.mouse = null;
    this.isDragging = false;
    this.previousMousePosition = { x: 0, y: 0 };
    this.targetRotation = { x: 0.35, y: 0.25 };
    this.currentRotation = { x: 0.35, y: 0.25 };
    this.shieldMode = 'hardened'; // 'hardened' or 'porous'
    this.alarmIntensity = 0;

    if (this.container && window.THREE) {
      this.init();
    }
  }

  init() {
    const width = this.container.clientWidth || 640;
    const height = this.container.clientHeight || 360;

    // 1. Scene
    this.scene = new THREE.Scene();

    // 2. Camera: Isometric studio perspective
    this.camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 1000);
    this.camera.position.set(0, 22, 38);
    this.camera.lookAt(0, 0, 0);

    // 3. Renderer: High-DPI transparent WebGL
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.shadowMap.enabled = true;
    this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    this.container.innerHTML = '';
    this.container.appendChild(this.renderer.domElement);

    // 4. Raycasting & Interaction
    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2();

    this.setupLights();
    this.createStudioGrid();
    this.createPipelineArchitecture();
    this.createAmbientDust();
    this.setupEventListeners();
    this.animate();
  }

  setupLights() {
    // Soft studio hemisphere light (sky soft pearl, ground light slate)
    const hemiLight = new THREE.HemisphereLight(0xffffff, 0xe2e8f0, 1.3);
    this.scene.add(hemiLight);

    // Key directional light casting soft shadows
    const dirLight = new THREE.DirectionalLight(0xffffff, 1.1);
    dirLight.position.set(15, 30, 20);
    this.scene.add(dirLight);

    // Subtle blue fill light from the left (Agent side)
    const agentFill = new THREE.PointLight(0x4f46e5, 1.8, 40);
    agentFill.position.set(-14, 4, 6);
    this.scene.add(agentFill);

    // Subtle emerald fill light from the right (Server side)
    const serverFill = new THREE.PointLight(0x10b981, 1.8, 40);
    serverFill.position.set(14, 4, 6);
    this.scene.add(serverFill);

    // Center shield point light
    this.shieldLight = new THREE.PointLight(0x06b6d4, 2.5, 35);
    this.shieldLight.position.set(0, 2, 0);
    this.scene.add(this.shieldLight);
  }

  createStudioGrid() {
    // Subtle studio floor grid
    const gridHelper = new THREE.GridHelper(44, 22, 0xcbd5e1, 0xf1f5f9);
    gridHelper.position.y = -4.5;
    this.scene.add(gridHelper);

    // Luminous data highway connecting Agent -> Shield -> Server
    const pathGeo = new THREE.PlaneGeometry(36, 1.2);
    const pathMat = new THREE.MeshBasicMaterial({
      color: 0x6366f1,
      transparent: true,
      opacity: 0.12,
      side: THREE.DoubleSide
    });
    const path = new THREE.Mesh(pathGeo, pathMat);
    path.rotation.x = Math.PI / 2;
    path.position.y = -4.4;
    this.scene.add(path);
  }

  createPipelineArchitecture() {
    this.pipelineGroup = new THREE.Group();
    this.scene.add(this.pipelineGroup);

    // ==========================================
    // 1. LEFT NODE: AI Coding Agent (x = -14)
    // ==========================================
    this.agentGroup = new THREE.Group();
    this.agentGroup.position.set(-14, 0, 0);

    // Agent Holographic Diamond Core
    const agentCoreGeo = new THREE.OctahedronGeometry(2.4, 0);
    const agentCoreMat = new THREE.MeshStandardMaterial({
      color: 0x4f46e5,
      metalness: 0.3,
      roughness: 0.2,
      transparent: true,
      opacity: 0.85
    });
    this.agentCore = new THREE.Mesh(agentCoreGeo, agentCoreMat);
    this.agentGroup.add(this.agentCore);

    // Agent Wireframe Outer Cage
    const agentCageGeo = new THREE.IcosahedronGeometry(3.2, 1);
    const agentCageMat = new THREE.MeshBasicMaterial({
      color: 0x818cf8,
      wireframe: true,
      transparent: true,
      opacity: 0.4
    });
    this.agentCage = new THREE.Mesh(agentCageGeo, agentCageMat);
    this.agentGroup.add(this.agentCage);

    // Agent Base Pedestal
    const agentBaseGeo = new THREE.CylinderGeometry(3.6, 4.0, 0.4, 32);
    const agentBaseMat = new THREE.MeshStandardMaterial({
      color: 0xe2e8f0,
      metalness: 0.6,
      roughness: 0.3
    });
    const agentBase = new THREE.Mesh(agentBaseGeo, agentBaseMat);
    agentBase.position.y = -4.2;
    this.agentGroup.add(agentBase);

    this.pipelineGroup.add(this.agentGroup);

    // ==========================================
    // 2. CENTER NODE: Quantum Guardrail Shield (x = 0)
    // ==========================================
    this.shieldGroup = new THREE.Group();
    this.shieldGroup.position.set(0, 0, 0);

    // Main Shield Hexagonal Energy Disc (Facing incoming attacks from left)
    const shieldDiscGeo = new THREE.CylinderGeometry(6.5, 6.5, 0.3, 6);
    this.shieldDiscMat = new THREE.MeshPhysicalMaterial({
      color: 0x06b6d4,
      emissive: 0x0891b2,
      emissiveIntensity: 0.3,
      roughness: 0.1,
      metalness: 0.1,
      transmission: 0.6,
      transparent: true,
      opacity: 0.82,
      ior: 1.5
    });
    this.shieldMesh = new THREE.Mesh(shieldDiscGeo, this.shieldDiscMat);
    this.shieldMesh.rotation.z = Math.PI / 2;
    this.shieldGroup.add(this.shieldMesh);

    // Interlocking Outer Security Rings
    const ring1Geo = new THREE.TorusGeometry(7.2, 0.18, 12, 48);
    const ring1Mat = new THREE.MeshStandardMaterial({
      color: 0x4f46e5,
      metalness: 0.7,
      roughness: 0.2
    });
    this.shieldRing1 = new THREE.Mesh(ring1Geo, ring1Mat);
    this.shieldRing1.rotation.y = Math.PI / 2;
    this.shieldGroup.add(this.shieldRing1);
    this.shieldRings.push(this.shieldRing1);

    const ring2Geo = new THREE.TorusGeometry(8.2, 0.14, 12, 48);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      wireframe: true,
      transparent: true,
      opacity: 0.6
    });
    this.shieldRing2 = new THREE.Mesh(ring2Geo, ring2Mat);
    this.shieldRing2.rotation.y = Math.PI / 2;
    this.shieldGroup.add(this.shieldRing2);
    this.shieldRings.push(this.shieldRing2);

    // Center Shield Base Pedestal
    const shieldBaseGeo = new THREE.CylinderGeometry(5.0, 5.4, 0.4, 32);
    const shieldBaseMat = new THREE.MeshStandardMaterial({
      color: 0xe2e8f0,
      metalness: 0.6,
      roughness: 0.3
    });
    const shieldBase = new THREE.Mesh(shieldBaseGeo, shieldBaseMat);
    shieldBase.position.y = -4.2;
    this.shieldGroup.add(shieldBase);

    this.pipelineGroup.add(this.shieldGroup);

    // ==========================================
    // 3. RIGHT NODE: Protected Host / Server Core (x = 14)
    // ==========================================
    this.serverGroup = new THREE.Group();
    this.serverGroup.position.set(14, 0, 0);

    // Monolith Server Protected Core
    const serverCoreGeo = new THREE.IcosahedronGeometry(2.5, 2);
    this.serverCoreMat = new THREE.MeshStandardMaterial({
      color: 0x059669,
      emissive: 0x10b981,
      emissiveIntensity: 0.25,
      metalness: 0.4,
      roughness: 0.2,
      transparent: true,
      opacity: 0.9
    });
    this.serverCore = new THREE.Mesh(serverCoreGeo, this.serverCoreMat);
    this.serverGroup.add(this.serverCore);

    // Server Orbital Rings
    const serverOrbitGeo = new THREE.TorusGeometry(3.6, 0.12, 12, 48);
    const serverOrbitMat = new THREE.MeshBasicMaterial({
      color: 0x34d399,
      wireframe: true,
      transparent: true,
      opacity: 0.5
    });
    this.serverOrbit = new THREE.Mesh(serverOrbitGeo, serverOrbitMat);
    this.serverOrbit.rotation.x = Math.PI / 3;
    this.serverGroup.add(this.serverOrbit);

    // Server Base Pedestal
    const serverBaseGeo = new THREE.CylinderGeometry(3.6, 4.0, 0.4, 32);
    const serverBaseMat = new THREE.MeshStandardMaterial({
      color: 0xe2e8f0,
      metalness: 0.6,
      roughness: 0.3
    });
    const serverBase = new THREE.Mesh(serverBaseGeo, serverBaseMat);
    serverBase.position.y = -4.2;
    this.serverGroup.add(serverBase);

    this.pipelineGroup.add(this.serverGroup);
  }

  createAmbientDust() {
    const particleCount = 120;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 60;
      positions[i + 1] = Math.random() * 20 - 4;
      positions[i + 2] = (Math.random() - 0.5) * 30;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const material = new THREE.PointsMaterial({
      size: 0.6,
      color: 0x6366f1,
      transparent: true,
      opacity: 0.25
    });

    this.ambientParticles = new THREE.Points(geometry, material);
    this.scene.add(this.ambientParticles);
  }

  setupEventListeners() {
    const dom = this.renderer.domElement;

    dom.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.previousMousePosition = { x: e.clientX, y: e.clientY };
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    dom.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        const deltaX = e.clientX - this.previousMousePosition.x;
        const deltaY = e.clientY - this.previousMousePosition.y;

        this.targetRotation.y += deltaX * 0.007;
        this.targetRotation.x += deltaY * 0.007;
        this.targetRotation.x = Math.max(-0.2, Math.min(0.8, this.targetRotation.x));

        this.previousMousePosition = { x: e.clientX, y: e.clientY };
      }

      const rect = dom.getBoundingClientRect();
      this.mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      this.mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    });

    window.addEventListener('resize', () => this.handleResize());
  }

  handleResize() {
    if (!this.container || !this.renderer || !this.camera) return;
    const width = this.container.clientWidth;
    const height = this.container.clientHeight;
    if (width === 0 || height === 0) return;

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }

  /**
   * Set Shield Appearance based on Guardrail Mode:
   * - 'hardened' (AST Mode): Brilliant cyan/emerald crystalline, solid impervious shield
   * - 'porous' (Regex / Literal Mode): Faint amber/red translucent, porous gaps
   */
  setShieldMode(mode) {
    this.shieldMode = mode;
    if (!this.shieldMesh || !this.shieldDiscMat) return;

    if (mode === 'hardened') {
      this.shieldDiscMat.color.setHex(0x06b6d4);
      this.shieldDiscMat.emissive.setHex(0x0891b2);
      this.shieldDiscMat.emissiveIntensity = 0.4;
      this.shieldDiscMat.opacity = 0.88;
      this.shieldLight.color.setHex(0x06b6d4);
      this.shieldRing1.material.color.setHex(0x4f46e5);
      this.shieldRing2.material.color.setHex(0x06b6d4);
    } else {
      // Porous / Vulnerable
      this.shieldDiscMat.color.setHex(0xf59e0b);
      this.shieldDiscMat.emissive.setHex(0xd97706);
      this.shieldDiscMat.emissiveIntensity = 0.2;
      this.shieldDiscMat.opacity = 0.45;
      this.shieldLight.color.setHex(0xf59e0b);
      this.shieldRing1.material.color.setHex(0xf59e0b);
      this.shieldRing2.material.color.setHex(0xef4444);
    }
  }

  setCameraView(viewName) {
    if (!this.camera) return;
    switch (viewName) {
      case 'iso':
        this.targetRotation.x = 0.35;
        this.targetRotation.y = 0.25;
        this.camera.position.set(0, 22, 38);
        break;
      case 'top':
        this.targetRotation.x = Math.PI / 2.3;
        this.targetRotation.y = 0;
        this.camera.position.set(0, 36, 12);
        break;
      case 'front':
        this.targetRotation.x = 0.05;
        this.targetRotation.y = 0;
        this.camera.position.set(0, 4, 38);
        break;
      case 'core':
        this.targetRotation.x = 0.2;
        this.targetRotation.y = -0.4;
        this.camera.position.set(10, 10, 24);
        break;
      default:
        this.targetRotation.x = 0.35;
        this.targetRotation.y = 0.25;
        this.camera.position.set(0, 22, 38);
    }
  }

  /**
   * Fires a command projectile from AI Agent (x: -14) towards Shield (x: 0)
   * - If BLOCKED: Projectile strikes shield at x: 0 and defOriginates explosive spark deflection
   * - If MISSED: Projectile penetrates shield, travels to x: 14, and triggers catastrophic breach alarm
   */
  fireProjectile(testCase, onImpact) {
    const status = testCase.status; // 'BLOCKED' or 'MISSED'
    const isBlocked = status === 'BLOCKED';

    // Start at AI Agent position
    const startX = -14;
    const startY = 0;
    const startZ = 0;

    // Target position
    // If blocked, target is the Shield surface (x = -0.5)
    // If missed, target is the Server Core (x = 14)
    const targetX = isBlocked ? -0.5 : 14;

    const projColor = isBlocked ? 0x10b981 : 0xef4444;

    // Glowing projectile capsule
    const projGeo = new THREE.SphereGeometry(0.7, 16, 16);
    const projMat = new THREE.MeshBasicMaterial({
      color: projColor,
      transparent: true,
      opacity: 0.95
    });
    const projectile = new THREE.Mesh(projGeo, projMat);
    projectile.position.set(startX, startY, startZ);
    this.scene.add(projectile);

    const projectileData = {
      mesh: projectile,
      startX,
      targetX,
      startY,
      startZ,
      status,
      isBlocked,
      color: projColor,
      progress: 0,
      speed: isBlocked ? 0.065 : 0.045, // Fast impact
      testCase,
      onImpact
    };

    this.projectiles.push(projectileData);
  }

  /**
   * Sequential fire for test suite with rapid visual rhythm
   */
  fireSuite(results) {
    let index = 0;
    const interval = setInterval(() => {
      if (index >= results.length) {
        clearInterval(interval);
        return;
      }
      this.fireProjectile(results[index]);
      index++;
    }, 120);
  }

  /**
   * Creates an explosive spark burst at given coordinate
   */
  createSparks(position, color, count = 35) {
    for (let i = 0; i < count; i++) {
      const sparkGeo = new THREE.BufferGeometry();
      const pos = new Float32Array([position.x, position.y, position.z]);
      sparkGeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));

      const sparkMat = new THREE.PointsMaterial({
        color,
        size: 0.85,
        transparent: true,
        opacity: 1
      });

      const spark = new THREE.Points(sparkGeo, sparkMat);
      
      // Deflection velocity: if blocked, bounce predominantly backwards (negative X)
      const isDeflection = color === 0x10b981 || color === 0x06b6d4;
      const vx = isDeflection 
        ? -Math.random() * 0.9 - 0.2 
        : (Math.random() - 0.5) * 0.8;
      const vy = (Math.random() - 0.5) * 0.9;
      const vz = (Math.random() - 0.5) * 0.9;

      const vel = new THREE.Vector3(vx, vy, vz);

      this.scene.add(spark);
      this.particles.push({ mesh: spark, velocity: vel, life: 1.0 });
    }
  }

  /**
   * Creates expanding energy shockwave ring
   */
  createShockwave(position, color, radius = 5.0) {
    const waveGeo = new THREE.RingGeometry(radius * 0.3, radius * 0.5, 32);
    const waveMat = new THREE.MeshBasicMaterial({
      color,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.85
    });
    const wave = new THREE.Mesh(waveGeo, waveMat);
    wave.position.copy(position);
    wave.rotation.y = Math.PI / 2;
    this.scene.add(wave);

    this.particles.push({
      mesh: wave,
      isWave: true,
      scaleSpeed: 0.09,
      life: 1.0
    });
  }

  triggerServerAlarm() {
    this.alarmIntensity = 1.0;
    if (this.serverCoreMat) {
      this.serverCoreMat.color.setHex(0xef4444);
      this.serverCoreMat.emissive.setHex(0xdc2626);
      this.serverCoreMat.emissiveIntensity = 0.8;
    }
  }

  animate() {
    this.animationFrameId = requestAnimationFrame(() => this.animate());

    // Smooth camera / scene rotation damping
    this.currentRotation.x += (this.targetRotation.x - this.currentRotation.x) * 0.08;
    this.currentRotation.y += (this.targetRotation.y - this.currentRotation.y) * 0.08;

    if (this.pipelineGroup) {
      this.pipelineGroup.rotation.x = this.currentRotation.x;
      this.pipelineGroup.rotation.y = this.currentRotation.y;
    }

    // Node ambient micro-animations
    if (this.agentCore) {
      this.agentCore.rotation.y += 0.015;
      this.agentCage.rotation.x += 0.008;
    }

    if (this.shieldMesh) {
      this.shieldMesh.rotation.x += 0.008; // Hex disc rotation
      this.shieldRing1.rotation.z += 0.012;
      this.shieldRing2.rotation.z -= 0.009;
    }

    if (this.serverCore) {
      this.serverCore.rotation.y += 0.01;
      this.serverOrbit.rotation.z += 0.015;
    }

    if (this.ambientParticles) {
      this.ambientParticles.rotation.y += 0.0006;
    }

    // Alarm cooldown decay
    if (this.alarmIntensity > 0) {
      this.alarmIntensity -= 0.02;
      if (this.alarmIntensity <= 0 && this.serverCoreMat) {
        this.serverCoreMat.color.setHex(0x059669);
        this.serverCoreMat.emissive.setHex(0x10b981);
        this.serverCoreMat.emissiveIntensity = 0.25;
      }
    }

    // Update active projectiles
    for (let i = this.projectiles.length - 1; i >= 0; i--) {
      const p = this.projectiles[i];
      p.progress += p.speed;

      // Linear interpolation along pipeline X axis with slight sinusoidal hover
      const currentX = p.startX + (p.targetX - p.startX) * p.progress;
      p.mesh.position.x = currentX;
      p.mesh.position.y = Math.sin(p.progress * Math.PI) * 0.6;
      p.mesh.position.z = 0;

      // When projectile hits target
      if (p.progress >= 1.0) {
        if (p.isBlocked) {
          // INTERCEPTED AT SHIELD (x = 0)
          const impactPos = new THREE.Vector3(0, 0, 0);
          this.createSparks(impactPos, 0x10b981, 40);
          this.createShockwave(impactPos, 0x06b6d4, 7.0);

          // Shield pulse animation
          if (this.shieldMesh) {
            this.shieldMesh.scale.set(1.2, 1.2, 1.2);
            setTimeout(() => {
              if (this.shieldMesh) this.shieldMesh.scale.set(1, 1, 1);
            }, 180);
          }
        } else {
          // BREACH: HIT PROTECTED SERVER (x = 14)
          const breachPos = new THREE.Vector3(14, 0, 0);
          this.createSparks(breachPos, 0xef4444, 50);
          this.createShockwave(breachPos, 0xef4444, 5.0);
          this.triggerServerAlarm();
        }

        if (p.onImpact) p.onImpact(p.testCase);

        this.scene.remove(p.mesh);
        this.projectiles.splice(i, 1);
      }
    }

    // Update particles (sparks & shockwaves)
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const part = this.particles[i];
      part.life -= 0.038;

      if (part.isWave) {
        part.mesh.scale.x += part.scaleSpeed;
        part.mesh.scale.y += part.scaleSpeed;
        part.mesh.material.opacity = part.life;
      } else {
        part.mesh.position.add(part.velocity);
        part.mesh.material.opacity = part.life;
      }

      if (part.life <= 0) {
        this.scene.remove(part.mesh);
        this.particles.splice(i, 1);
      }
    }

    if (this.renderer && this.scene && this.camera) {
      this.renderer.render(this.scene, this.camera);
    }
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    if (this.renderer && this.renderer.domElement) {
      this.renderer.domElement.remove();
    }
  }
}
