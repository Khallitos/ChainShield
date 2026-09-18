import QuizModule from "./QuizModule.jsx";
import SlidesModule from "./SlidesModule.jsx";
import VideoModule from "./VideoModule.jsx";
import TaskModule from "./TaskModule.jsx";

export default function ModulePlayer({ module, onComplete, onBack }) {
  const typeLabel = {
    quiz: "Quiz",
    slides: "Slides",
    video: "Video",
    task: "Practical task"
  }[module.type] ?? module.type;

  return (
    <div className="player-wrap">
      <button type="button" className="back-btn" onClick={onBack}>
        ← Back to course
      </button>
      <div className="player-header">
        <span className="type-pill">{typeLabel}</span>
        <h2>{module.title}</h2>
        <p className="muted">{module.duration} estimated</p>
      </div>

      {module.type === "video" && <VideoModule module={module} onComplete={onComplete} />}
      {module.type === "slides" && <SlidesModule module={module} onComplete={onComplete} />}
      {module.type === "quiz" && <QuizModule module={module} onComplete={onComplete} />}
      {module.type === "task" && <TaskModule module={module} onComplete={onComplete} />}
    </div>
  );
}
