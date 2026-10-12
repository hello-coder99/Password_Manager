/**
 * Configurable inactivity auto-lock timer for the unlocked vault.
 * Defaults to 5 minutes (300,000 ms) of inactivity.
 */

export const DEFAULT_INACTIVITY_MINUTES = 5;

export class AutoLockMonitor {
  /**
   * @param {object} options
   * @param {number} [options.timeoutMinutes=5]
   * @param {() => void} options.onLock
   * @param {(remainingSeconds: number) => void} [options.onTick]
   */
  constructor({
    timeoutMinutes = DEFAULT_INACTIVITY_MINUTES,
    onLock,
    onTick = null,
  }) {
    if (typeof onLock !== "function") {
      throw new TypeError("AutoLockMonitor requires an onLock callback.");
    }
    this.timeoutMinutes = this._clampMinutes(timeoutMinutes);
    this.onLock = onLock;
    this.onTick = onTick;
    this.deadlineMs = 0;
    this.intervalId = null;
    this.isRunning = false;

    this._boundActivityHandler = () => {
      if (this.isRunning) {
        this.resetTimer();
      }
    };
    this._activityEvents = [
      "mousedown",
      "keydown",
      "pointerdown",
      "touchstart",
      "scroll",
    ];
  }

  _clampMinutes(minutes) {
    const parsed = Number(minutes);
    if (!Number.isFinite(parsed) || parsed < 1) {
      return DEFAULT_INACTIVITY_MINUTES;
    }
    return Math.min(Math.round(parsed), 120);
  }

  setTimeoutMinutes(minutes) {
    this.timeoutMinutes = this._clampMinutes(minutes);
    if (this.isRunning) {
      this.resetTimer();
    }
  }

  start() {
    if (this.isRunning) {
      this.resetTimer();
      return;
    }
    this.isRunning = true;
    this.resetTimer();

    if (typeof window !== "undefined") {
      for (const evt of this._activityEvents) {
        window.addEventListener(evt, this._boundActivityHandler, {
          passive: true,
        });
      }
    }

    this.intervalId = setInterval(() => this._checkDeadline(), 1000);
  }

  resetTimer() {
    this.deadlineMs = Date.now() + this.timeoutMinutes * 60 * 1000;
    this._emitTick();
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (typeof window !== "undefined") {
      for (const evt of this._activityEvents) {
        window.removeEventListener(evt, this._boundActivityHandler);
      }
    }
  }

  getRemainingSeconds() {
    if (!this.isRunning) {
      return 0;
    }
    return Math.max(0, Math.ceil((this.deadlineMs - Date.now()) / 1000));
  }

  _emitTick() {
    if (typeof this.onTick === "function") {
      this.onTick(this.getRemainingSeconds());
    }
  }

  _checkDeadline() {
    if (!this.isRunning) {
      return;
    }
    const remaining = this.getRemainingSeconds();
    this._emitTick();
    if (remaining <= 0) {
      this.stop();
      this.onLock();
    }
  }
}
