import type { PackageReport, TrustReport } from '../src/core/index.js';

interface Node {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  p?: PackageReport;
  infectedAt: number;
  owned: boolean;
  depth: number;
  angle: number;
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

export class TrustGraph {
  private ctx: CanvasRenderingContext2D;
  private nodes: Node[] = [];
  private byId = new Map<string, Node>();
  private edges: [Node, Node][] = [];
  private parents = new Map<string, string[]>();
  private w = 0;
  private h = 0;
  private hover: Node | null = null;
  private raf = 0;
  private phishStart = 0;
  private alpha = 1;
  private maxDepth = 1;

  private ringR(d: number) {
    const max = Math.min(this.w / 2, (this.h / 2) * 1.35) - 16;
    const first = Math.min(110, max * 0.32);
    return d === 0 ? 0 : first + ((max - first) * (d - 1)) / Math.max(1, this.maxDepth - 1);
  }
  onPick: (name: string) => void = () => {};
  onTick: (infectedDirect: number) => void = () => {};

  constructor(private canvas: HTMLCanvasElement, private tip: HTMLElement) {
    this.ctx = canvas.getContext('2d')!;
    new ResizeObserver(() => this.resize()).observe(canvas);
    canvas.addEventListener('mousemove', (e) => this.move(e));
    canvas.addEventListener('mouseleave', () => {
      this.hover = null;
      tip.hidden = true;
    });
    canvas.addEventListener('click', () => this.hover && this.hover.p && this.onPick(this.hover.p.name));
  }

  load(packages: PackageReport[], trust: TrustReport) {
    cancelAnimationFrame(this.raf);
    this.resize();
    const byName = new Map<string, PackageReport>();
    for (const p of packages) if (!byName.has(p.name)) byName.set(p.name, p);
    const root: Node = { id: '', x: this.w / 2, y: this.h / 2, vx: 0, vy: 0, r: 9, infectedAt: 0, owned: false, depth: 0, angle: 0 };
    this.nodes = [root];
    this.byId = new Map([['', root]]);
    for (const [name, p] of byName) {
      const n: Node = { id: name, x: 0, y: 0, vx: 0, vy: 0, r: p.direct ? 4.5 : 2.6, p, infectedAt: 0, owned: false, depth: -1, angle: 0 };
      if (p.verdict === 'danger') n.r += 2;
      this.nodes.push(n);
      this.byId.set(name, n);
    }
    // Breadth-first depth from your app, children placed near their parent's angle.
    const kids = new Map<string, string[]>();
    for (const [a, b] of trust.edges) {
      if (!kids.has(a)) kids.set(a, []);
      kids.get(a)!.push(b);
    }
    const order: Node[] = [];
    let layer = [root];
    root.depth = 0;
    while (layer.length) {
      const next: Node[] = [];
      for (const n of layer) for (const k of kids.get(n.id) || []) {
        const c = this.byId.get(k);
        if (c && c.depth < 0) {
          c.depth = n.depth + 1;
          next.push(c);
        }
      }
      order.push(...next);
      layer = next;
    }
    const maxDepth = Math.max(1, ...this.nodes.map((n) => n.depth));
    for (const n of this.nodes) if (n.depth < 0) n.depth = maxDepth;
    this.maxDepth = maxDepth;
    const perDepth = new Map<number, Node[]>();
    for (const n of order) {
      if (!perDepth.has(n.depth)) perDepth.set(n.depth, []);
      perDepth.get(n.depth)!.push(n);
    }
    for (const n of this.nodes) if (n.depth === maxDepth && !order.includes(n) && n !== root) {
      if (!perDepth.has(maxDepth)) perDepth.set(maxDepth, []);
      perDepth.get(maxDepth)!.push(n);
    }
    for (const [d, list] of perDepth) {
      list.forEach((n, i) => {
        n.angle = (i / list.length) * Math.PI * 2 + d * 0.7;
        const r = this.ringR(d);
        n.x = this.w / 2 + Math.cos(n.angle) * r;
        n.y = this.h / 2 + (Math.sin(n.angle) * r) / 1.35;
      });
    }
    this.edges = [];
    this.parents = new Map();
    for (const [a, b] of trust.edges) {
      const na = this.byId.get(a);
      const nb = this.byId.get(b);
      if (!na || !nb) continue;
      this.edges.push([na, nb]);
      if (!this.parents.has(b)) this.parents.set(b, []);
      this.parents.get(b)!.push(a);
    }
    this.alpha = 1;
    this.phishStart = 0;
    for (let k = 0; k < 220; k++) this.step();
    this.loop();
  }

  /** Light up an account's packages, then let the infection climb to your app. */
  phish(owned: string[]) {
    for (const n of this.nodes) {
      n.infectedAt = 0;
      n.owned = false;
    }
    const now = performance.now();
    this.phishStart = now;
    let layer = owned.map((o) => this.byId.get(o)).filter(Boolean) as Node[];
    const seen = new Set(layer.map((n) => n.id));
    layer.forEach((n) => {
      n.owned = true;
      n.infectedAt = now + 1;
    });
    let depth = 1;
    while (layer.length) {
      const next: Node[] = [];
      for (const n of layer) {
        for (const pid of this.parents.get(n.id) || []) {
          if (seen.has(pid)) continue;
          seen.add(pid);
          const pn = this.byId.get(pid)!;
          pn.infectedAt = now + depth * 320;
          next.push(pn);
        }
      }
      layer = next;
      depth++;
    }
  }

  clearPhish() {
    for (const n of this.nodes) {
      n.infectedAt = 0;
      n.owned = false;
    }
    this.phishStart = 0;
  }

  private resize() {
    const dpr = window.devicePixelRatio || 1;
    const rect = this.canvas.getBoundingClientRect();
    if (!rect.width) return;
    this.w = rect.width;
    this.h = rect.height;
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  private step() {
    const N = this.nodes;
    const cx = this.w / 2;
    const cy = this.h / 2;
    const k = this.alpha;
    for (let i = 0; i < N.length; i++) {
      const a = N[i];
      for (let j = i + 1; j < N.length; j++) {
        const b = N[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy + 0.01;
        if (d2 > 900) continue;
        const f = (14 / d2) * k;
        a.vx += dx * f;
        a.vy += dy * f;
        b.vx -= dx * f;
        b.vy -= dy * f;
      }
    }
    for (const [a, b] of this.edges) {
      if (a.id === '') continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      a.vx += dx * 0.002 * k;
      a.vy += dy * 0.002 * k;
      b.vx -= dx * 0.002 * k;
      b.vy -= dy * 0.002 * k;
    }
    for (const n of N) {
      if (n.id === '') {
        n.x = cx;
        n.y = cy;
        continue;
      }
      // Pull each node onto its ring (ellipse to use the wide canvas).
      const dx = (n.x - cx) / 1.35;
      const dy = n.y - cy;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const target = this.ringR(n.depth) / 1.35;
      const f = ((target - d) / d) * 0.12;
      n.vx += dx * f * 1.35;
      n.vy += dy * f;
      n.vx *= 0.55;
      n.vy *= 0.55;
      n.x = Math.max(6, Math.min(this.w - 6, n.x + n.vx));
      n.y = Math.max(6, Math.min(this.h - 6, n.y + n.vy));
    }
    this.alpha = Math.max(0.02, this.alpha * 0.985);
  }

  private loop = () => {
    if (this.alpha > 0.03) this.step();
    this.draw();
    this.raf = requestAnimationFrame(this.loop);
  };

  private draw() {
    const c = this.ctx;
    const t = performance.now();
    const ink = css('--ink');
    const line = css('--line');
    const danger = css('--danger');
    const review = css('--review');
    const muted = css('--ink-3');
    c.clearRect(0, 0, this.w, this.h);
    const infected = (n: Node) => n.infectedAt > 0 && t >= n.infectedAt;

    c.lineWidth = 1;
    c.strokeStyle = line;
    c.globalAlpha = 0.5;
    for (let d = 1; d <= this.maxDepth; d++) {
      const r = this.ringR(d);
      c.beginPath();
      c.ellipse(this.w / 2, this.h / 2, r, r / 1.35, 0, 0, Math.PI * 2);
      c.stroke();
    }
    c.globalAlpha = 1;
    for (const [a, b] of this.edges) {
      const hot = infected(a) && infected(b);
      c.strokeStyle = hot ? danger : line;
      c.globalAlpha = hot ? 0.9 : 0.7;
      c.beginPath();
      c.moveTo(a.x, a.y);
      c.lineTo(b.x, b.y);
      c.stroke();
    }
    c.globalAlpha = 1;
    let directHit = 0;
    for (const n of this.nodes) {
      const hit = infected(n);
      if (hit && n.p?.direct) directHit++;
      let fill = n.id === '' ? ink : muted;
      if (n.p?.verdict === 'review') fill = review;
      if (n.p?.verdict === 'danger') fill = danger;
      if (hit) fill = danger;
      if (hit) {
        const age = (t - n.infectedAt) / 1000;
        const pulse = n.owned ? 6 + 4 * Math.sin(t / 180) : Math.max(0, 10 - age * 14);
        if (pulse > 0) {
          c.fillStyle = danger;
          c.globalAlpha = 0.18;
          c.beginPath();
          c.arc(n.x, n.y, n.r + pulse, 0, Math.PI * 2);
          c.fill();
          c.globalAlpha = 1;
        }
      }
      c.fillStyle = fill;
      c.beginPath();
      c.arc(n.x, n.y, n.r + (n === this.hover ? 2 : 0), 0, Math.PI * 2);
      c.fill();
    }
    const root = this.byId.get('');
    if (root) {
      c.font = '600 12px Inter Tight, sans-serif';
      c.fillStyle = infected(root) ? danger : ink;
      c.textAlign = 'center';
      c.lineWidth = 5;
      c.strokeStyle = css('--paper');
      c.strokeText(infected(root) ? 'your app (compromised)' : 'your app', root.x, root.y - 16);
      c.fillText(infected(root) ? 'your app (compromised)' : 'your app', root.x, root.y - 16);
    }
    if (this.phishStart) this.onTick(directHit);
  }

  private move(e: MouseEvent) {
    const rect = this.canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    let best: Node | null = null;
    let bd = 144;
    for (const n of this.nodes) {
      const d = (n.x - x) ** 2 + (n.y - y) ** 2;
      if (d < bd) {
        bd = d;
        best = n;
      }
    }
    this.hover = best;
    this.canvas.style.cursor = best?.p ? 'pointer' : 'default';
    if (best?.p) {
      const p = best.p;
      this.tip.hidden = false;
      this.tip.innerHTML = `<b>${esc(p.name)}</b>${p.version ? '@' + esc(p.version) : ''}<br><span>${p.verdict} · ${esc((p.meta.maintainers || []).slice(0, 3).join(', ')) || 'no maintainers listed'}${(p.meta.maintainers || []).length > 3 ? '…' : ''}</span>`;
      this.tip.style.left = `${Math.min(x + 14, rect.width - 220)}px`;
      this.tip.style.top = `${y + 14}px`;
    } else this.tip.hidden = true;
  }
}
