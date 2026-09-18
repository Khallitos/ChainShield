export default function TaskModule({ module, onComplete }) {
  return (
    <div className="task-wrap">
      <p>{module.description}</p>
      <a href={module.fileSrc} className="btn secondary file-btn" download>
        📄 {module.fileLabel}
      </a>
      <p className="small" style={{ marginTop: 14 }}>
        Once you have completed the exercise, click below to mark it done.
      </p>
      <button type="button" className="btn" onClick={() => onComplete(true)}>
        Mark as complete ✓
      </button>
    </div>
  );
}
