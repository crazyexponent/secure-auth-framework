// ── PARTICLE SYSTEM ──
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let particles = [];

function resizeCanvas(){
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

class Particle {
  constructor(){
    this.reset();
  }
  reset(){
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 2 + 0.5;
    this.speedX = (Math.random() - 0.5) * 0.4;
    this.speedY = (Math.random() - 0.5) * 0.4;
    this.opacity = Math.random() * 0.5 + 0.1;
    this.hue = Math.random() > 0.5 ? 200 : 260;
  }
  update(){
    this.x += this.speedX;
    this.y += this.speedY;
    if(this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) this.reset();
  }
  draw(){
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fillStyle = `hsla(${this.hue},80%,70%,${this.opacity})`;
    ctx.fill();
  }
}

for(let i = 0; i < 80; i++) particles.push(new Particle());

function drawLines(){
  for(let i = 0; i < particles.length; i++){
    for(let j = i + 1; j < particles.length; j++){
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if(dist < 150){
        ctx.beginPath();
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(particles[j].x, particles[j].y);
        ctx.strokeStyle = `rgba(56,189,248,${0.06 * (1 - dist/150)})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
    }
  }
}

function animateParticles(){
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  particles.forEach(p => { p.update(); p.draw(); });
  drawLines();
  requestAnimationFrame(animateParticles);
}
animateParticles();

// ── LOADER ──
window.addEventListener('load', () => {
  setTimeout(() => {
    document.getElementById('loader').classList.add('hidden');
  }, 2400);
});

// ── NAVBAR SCROLL EFFECT ──
const navbar = document.querySelector('.navbar');
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 50);
});

// ── NAV LINK ACTIVE STATE ──
document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', function(e){
    e.preventDefault();
    document.querySelectorAll('.nav-links a').forEach(l => l.classList.remove('active'));
    this.classList.add('active');
    const target = document.querySelector(this.getAttribute('href'));
    if(target) target.scrollIntoView({behavior:'smooth'});
  });
});

// ── SCROLL REVEAL ──
const revealElements = document.querySelectorAll('.reveal');
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if(entry.isIntersecting){
      entry.target.classList.add('visible');
    }
  });
}, {threshold: 0.1});
revealElements.forEach(el => revealObserver.observe(el));

// ── TERMINAL ──
const terminal = document.getElementById('terminal');

function addLog(msg, color){
  if(!terminal) return;
  const line = document.createElement('div');
  line.textContent = msg;
  if(color) line.style.color = color;
  line.style.opacity = '0';
  line.style.transform = 'translateX(-10px)';
  terminal.appendChild(line);
  requestAnimationFrame(() => {
    line.style.transition = 'opacity .3s, transform .3s';
    line.style.opacity = '1';
    line.style.transform = 'translateX(0)';
  });
  terminal.scrollTop = terminal.scrollHeight;
}

// ── ATTACK SIMULATION ──
function simulateAttack(){
  const steps = [
    {msg: '', delay: 0},
    {msg: '╔═══════════════════════════════════════╗', color: '#f87171', delay: 200},
    {msg: '║   ATTACK SIMULATION INITIATED         ║', color: '#f87171', delay: 300},
    {msg: '╚═══════════════════════════════════════╝', color: '#f87171', delay: 400},
    {msg: '', delay: 600},
    {msg: '$ sudo -u root /bin/bash', color: '#64748b', delay: 800},
    {msg: '  [RBAC] Checking privilege hierarchy...', color: '#eab308', delay: 1200},
    {msg: '  [RBAC] Current Role  : USER (level 2)', color: '#94a3b8', delay: 1600},
    {msg: '  [RBAC] Requested Role: ROOT (level 4)', color: '#94a3b8', delay: 2000},
    {msg: '  [RBAC] Required clearance: LEVEL 4', color: '#94a3b8', delay: 2400},
    {msg: '', delay: 2600},
    {msg: '  ✗ ACCESS DENIED — Insufficient privileges', color: '#f87171', delay: 2800},
    {msg: '  ✗ Privilege escalation attempt BLOCKED', color: '#f87171', delay: 3200},
    {msg: '  ✓ Security audit event logged', color: '#eab308', delay: 3600},
    {msg: '  ✓ Alert dispatched to system administrator', color: '#eab308', delay: 4000},
    {msg: '  ✓ Operating system protected successfully', color: '#4ade80', delay: 4400},
  ];
  steps.forEach(s => setTimeout(() => addLog(s.msg, s.color), s.delay));
}

