const video = document.querySelector(".video");
const playPauseBtn = document.querySelector(".play-pause");
const volumeInput = document.querySelector(".volume-control");
const currentTimeDisplay = document.querySelector(".current-time");
const videoDurationDisplay = document.querySelector(".video-duration");
const progressBar = document.querySelector(".progress-bar");
const progressArea = document.querySelector(".progress-area");
const skipBackwardBtn = document.querySelector(".skip-backward");
const skipForwardBtn = document.querySelector(".skip-forward");
const fullscreenBtn = document.querySelector(".fullscreen");
const volumeBtn = document.querySelector(".volume");

// Play/Pause video
playPauseBtn.addEventListener("click", () => {
  if (video.paused) {
    video.play();
    playPauseBtn.innerHTML = '<i class="fas fa-pause"></i>';
  } else {
    video.pause();
    playPauseBtn.innerHTML = '<i class="fas fa-play"></i>';
  }
});

// Volume control
volumeInput.addEventListener("input", () => {
  video.volume = volumeInput.value;
  if (video.volume === 0) {
    volumeBtn.innerHTML = '<i class="fas fa-volume-mute"></i>';
  } else {
    volumeBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
  }
});

// Mute Button
volumeBtn.addEventListener("click", () => {
  if (video.volume > 0) {
    video.volume = 0;
    volumeBtn.innerHTML = '<i class="fas fa-volume-mute"></i>';
  } else {
    video.volume = volumeInput.value;
    volumeBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
  }
});

// Skip backward 10 seconds
skipBackwardBtn.addEventListener("click", () => {
  video.currentTime -= 10;
});

// Skip forward 10 seconds
skipForwardBtn.addEventListener("click", () => {
  video.currentTime += 10;
});

// Update video time and progress bar
video.addEventListener("timeupdate", () => {
  const currentTime = video.currentTime;
  const duration = video.duration;
  const progress = (currentTime / duration) * 100;

  progressBar.style.width = `${progress}%`;
  currentTimeDisplay.textContent = formatTime(currentTime);
  videoDurationDisplay.textContent = formatTime(duration);
});

// Video progress bar click to change position
progressArea.addEventListener("click", (e) => {
  const width = progressArea.clientWidth;
  const clickX = e.offsetX;
  const duration = video.duration;
  video.currentTime = (clickX / width) * duration;
});

// Fullscreen toggle
fullscreenBtn.addEventListener("click", () => {
  if (!document.fullscreenElement) {
    video.requestFullscreen();
  } else {
    document.exitFullscreen();
  }
});

// Format time from seconds to mm:ss
function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}:${secs < 10 ? "0" + secs : secs}`;
}

// Auto play when video is ready
video.addEventListener("canplay", () => {
  video.play();
  playPauseBtn.innerHTML = '<i class="fas fa-pause"></i>';
});
