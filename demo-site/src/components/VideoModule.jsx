export default function VideoModule({ module, onComplete }) {
  return (
    <div className="video-wrap">
      <div className="video-frame">
        <iframe
          src={module.src}
          title={module.title}
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
          allowFullScreen
        />
      </div>
      <p className="video-desc">{module.description}</p>
      <button type="button" className="btn" onClick={() => onComplete(true)}>
        Mark as watched ✓
      </button>
    </div>
  );
}
