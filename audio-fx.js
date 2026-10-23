/**
 * Guardrail Lab — Procedural Web Audio Synthesizer
 * 
 * Zero external dependencies. Uses the browser's native Web Audio API
 * to synthesize real-time sci-fi sound effects for the defense arena:
 * - Laser Fire (frequency-sweep oscillator)
 * - Shield Deflect (crystalline harmonic chime)
 * - Core Breach (heavy sub-bass drop & dissonant warning klaxon)
 * - Terminal Typing (subtle mechanical click)
 */

class SoundSynthesizer {
  constructor() {
    this.ctx = null;
    this.muted = localStorage.getItem('guardrail_sound_muted') === 'true';
    this.initialized = false;
  }

  init() {
    if (this.initialized && this.ctx) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
        this.initialized = true;
      }
    } catch (e) {
      console.warn('Web Audio not supported:', e);
    }
  }

  ensureContext() {
    this.init();
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume();
    }
  }

  toggleMute() {
    this.muted = !this.muted;
    localStorage.setItem('guardrail_sound_muted', String(this.muted));
    return this.muted;
  }

  isMuted() {
    return this.muted;
  }

  /**
   * Sci-fi laser projectile launch sound
   */
  playLaser() {
    if (this.muted) return;
    this.ensureContext();
    if (!this.ctx) return;

    try {
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sawtooth';
      // Pitch drop: 880Hz down to 110Hz in 120ms
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(110, now + 0.12);

      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.13);
    } catch (_) {}
  }

  /**
   * Crystalline shield ricochet / deflection chime (Harmonic sine waves)
   */
  playDeflect() {
    if (this.muted) return;
    this.ensureContext();
    if (!this.ctx) return;

    try {
      const now = this.ctx.currentTime;
      const fundamental = 587.33; // D5
      const harmonics = [1, 1.5, 2, 2.75]; // Crystal chord

      harmonics.forEach((ratio, idx) => {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();

        osc.type = 'sine';
        osc.frequency.setValueAtTime(fundamental * ratio, now);

        const initialVol = 0.08 / (idx + 1);
        const duration = 0.35 + idx * 0.08;

        gain.gain.setValueAtTime(initialVol, now);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

        osc.connect(gain);
        gain.connect(this.ctx.destination);

        osc.start(now);
        osc.stop(now + duration + 0.01);
      });
    } catch (_) {}
  }

  /**
   * Critical breach alarm: Heavy sub-bass pulse + dissonant tritone alarm
   */
  playBreach() {
    if (this.muted) return;
    this.ensureContext();
    if (!this.ctx) return;

    try {
      const now = this.ctx.currentTime;

      // 1. Heavy Sub-bass impact
      const subOsc = this.ctx.createOscillator();
      const subGain = this.ctx.createGain();

      subOsc.type = 'sine';
      subOsc.frequency.setValueAtTime(140, now);
      subOsc.frequency.exponentialRampToValueAtTime(35, now + 0.4);

      subGain.gain.setValueAtTime(0.3, now);
      subGain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);

      subOsc.connect(subGain);
      subGain.connect(this.ctx.destination);

      subOsc.start(now);
      subOsc.stop(now + 0.46);

      // 2. Dual Dissonant Alarm Klaxon
      const freqs = [330, 466.16]; // Tritone dissonance (E4 + Bb4)
      freqs.forEach(freq => {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();

        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(freq, now + 0.05);

        gain.gain.setValueAtTime(0.08, now + 0.05);
        gain.gain.linearRampToValueAtTime(0.12, now + 0.15);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);

        osc.connect(gain);
        gain.connect(this.ctx.destination);

        osc.start(now + 0.05);
        osc.stop(now + 0.42);
      });
    } catch (_) {}
  }

  /**
   * Subtle typewriter mechanical tap
   */
  playClick() {
    if (this.muted) return;
    this.ensureContext();
    if (!this.ctx) return;

    try {
      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(1800 + Math.random() * 400, now);

      gain.gain.setValueAtTime(0.02, now);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.03);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.035);
    } catch (_) {}
  }
}

export const audioFx = new SoundSynthesizer();
