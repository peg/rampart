(() => {
  'use strict';
  const canvas = document.querySelector('.boundary-canvas');
  const scene = document.querySelector('.threshold-figure');
  const journey = document.querySelector('.hero');
  if (!canvas || !scene || !journey || !window.ResizeObserver || !window.IntersectionObserver) return;
  const context = canvas.getContext('2d');
  if (!context) return;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const narrow = matchMedia('(max-width: 959px)');
  let width = 0, height = 0, pixelRatio = 0, progress = 0, frame = 0, visible = true;
  const clamp = value => Math.max(0, Math.min(1, value));
  const smooth = value => { const t = clamp(value); return t * t * (3 - 2 * t); };

  function draw() {
    context.clearRect(0, 0, width, height);
    const unfold = smooth(progress * 1.6);
    const align = smooth((progress - .55) / .45);
    const yaw = (.55 - unfold * .28 + align * .18);
    const pitch = .31 + unfold * .13;
    const scale = Math.min(width / 480, height / 440);
    const project = (x, y, z) => [
      width * .51 + (x * Math.cos(yaw) - z * Math.sin(yaw)) * scale,
      height * .66 + (-y * Math.cos(pitch) + (z * Math.cos(yaw) + x * Math.sin(yaw)) * Math.sin(pitch)) * scale
    ];
    const path = (points, fill, stroke, weight = .8) => {
      context.beginPath();
      points.forEach((point, index) => {
        const screen = project(...point);
        if (index) context.lineTo(...screen); else context.moveTo(...screen);
      });
      context.closePath();
      if (fill) { context.fillStyle = fill; context.fill(); }
      if (stroke) { context.strokeStyle = stroke; context.lineWidth = weight; context.stroke(); }
    };
    const arch = ({ z, shift: y, shade }) => {
      const back = z - 13, front = z + 13;
      const face = (points, color) => path(points, color, '#ac819744');
      // The camera stays above/right of the front. These are the exposed
      // walls and top of one joined arch; its pillar-to-beam caps are internal.
      face([[105,y,back],[105,y,front],[105,239+y,front],[105,239+y,back]], shade[1]);
      face([[-72,y,back],[-72,205+y,back],[-72,205+y,front],[-72,y,front]], shade[1]);
      face([[-105,239+y,back],[-105,239+y,front],[105,239+y,front],[105,239+y,back]], shade[2]);
      face([[-105,y,front],[-72,y,front],[-72,205+y,front],[72,205+y,front],
        [72,y,front],[105,y,front],[105,239+y,front],[-105,239+y,front]], shade[0]);
    };
    path([[-165,-5,-175],[165,-5,-175],[165,-5,190],[-165,-5,190]], '#151013', '#6e3f5355');
    path([[-165,-5,190],[165,-5,190],[165,-15,190],[-165,-15,190]], '#21151c', '#5e3b4b66');
    for (let z = -150; z <= 150; z += 50) path([[-155,-4,z],[155,-4,z]], null, '#7d526222', .6);
    for (let x = -150; x <= 150; x += 50) path([[x,-4,-170],[x,-4,185]], null, '#7d526222', .6);
    path([[-150,-3,0],[150,-3,0]], null, '#ff4f9aaa', 1);

    const layers = [
      { z: -29 - unfold * 77, shift: -unfold * 22, shade: ['#211b20','#3c2a35','#6b4e5e'] },
      { z: 0, shift: unfold * 15, shade: ['#39222e','#6c344e','#b35780'] },
      { z: 29 + unfold * 77, shift: unfold * 46, shade: ['#292328','#4e3c47','#887280'] }
    ];
    // The z slabs never overlap, so complete layers draw back-to-front.
    // The policy plane sits in the gap just behind the middle slab (z=-13).
    // It illustrates the configured boundary, not a process sandbox or an
    // independently witnessed execution record.
    layers.forEach((layer, index) => {
      if (index === 1) path([[-71,0,-14],[-71,203,-14],[71,203,-14],[71,0,-14]], '#ff4f9a0a', '#ff78b477');
      arch(layer);
    });

    if (unfold > .2 && !narrow.matches) {
      context.globalAlpha = clamp((unfold - .2) / .45);
      context.font = '500 12px Manrope, sans-serif';
      context.fillStyle = '#dbc4cf';
      const labels = ['RECORD', 'POLICY', 'ACTION'];
      layers.forEach((layer, index) => {
        const a = project(112, 30 + layer.shift, layer.z);
        const b = project(154, 30 + layer.shift, layer.z);
        context.beginPath(); context.moveTo(...a); context.lineTo(...b);
        context.lineWidth = .7; context.strokeStyle = '#c07599'; context.stroke();
        context.textAlign = 'right';
        context.fillText(labels[index], Math.min(width - 8, b[0] + 40), b[1] + 18);
      });
      context.globalAlpha = 1;
    }
  }

  function render() {
    frame = 0;
    if (!visible || document.hidden) return;
    const rect = scene.getBoundingClientRect();
    const ratio = Math.min(devicePixelRatio || 1, 1.75);
    if (width !== rect.width || height !== rect.height || pixelRatio !== ratio) {
      width = rect.width; height = rect.height; pixelRatio = ratio;
      canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    }
    if (!width || !height) return;
    const bounds = journey.getBoundingClientRect();
    progress = narrow.matches || reduced.matches ? .64 : clamp(-bounds.top / Math.max(1, bounds.height - innerHeight));
    draw();
  }
  function schedule() {
    if (!frame && visible && !document.hidden) frame = requestAnimationFrame(render);
  }
  new ResizeObserver(schedule).observe(scene);
  new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    if (visible) schedule(); else { cancelAnimationFrame(frame); frame = 0; }
  }).observe(scene);
  addEventListener('scroll', () => {
    if (!narrow.matches && !reduced.matches) schedule();
  }, { passive: true });
  addEventListener('resize', schedule, { passive: true });
  document.addEventListener('visibilitychange', schedule);
  reduced.addEventListener('change', schedule);
  narrow.addEventListener('change', schedule);
  document.documentElement.classList.add('scene-ready');
  schedule();
})();
