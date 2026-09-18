import { useState } from "react";

export default function QuizModule({ module, onComplete }) {
  const { questions } = module;
  const [idx, setIdx] = useState(0);
  const [chosen, setChosen] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [score, setScore] = useState(0);
  const [done, setDone] = useState(false);

  const q = questions[idx];
  const correct = chosen === q.answer;

  function handleSubmit() {
    if (chosen === null) return;
    setSubmitted(true);
    if (correct) setScore((s) => s + 1);
  }

  function handleNext() {
    if (idx + 1 < questions.length) {
      setIdx((i) => i + 1);
      setChosen(null);
      setSubmitted(false);
    } else {
      setDone(true);
    }
  }

  if (done) {
    const pct = Math.round((score / questions.length) * 100);
    const pass = pct >= 70;
    return (
      <div className="quiz-result">
        <div className={`result-icon ${pass ? "pass" : "fail"}`}>{pass ? "✓" : "✗"}</div>
        <h3>{pass ? "Well done!" : "Keep going!"}</h3>
        <p>
          You scored <strong>{score} / {questions.length}</strong> ({pct}%).
          {pass ? " You passed this module." : " Review the lesson and try again."}
        </p>
        <button type="button" className="btn" onClick={() => onComplete(pass)}>
          {pass ? "Complete lesson" : "Retry quiz"}
        </button>
      </div>
    );
  }

  return (
    <div className="quiz-wrap">
      <div className="quiz-progress">
        Question {idx + 1} of {questions.length}
        <span className="quiz-bar">
          <span style={{ width: `${((idx) / questions.length) * 100}%` }} />
        </span>
      </div>

      <p className="quiz-q">{q.q}</p>

      <div className="quiz-options">
        {q.options.map((opt, i) => {
          let cls = "quiz-opt";
          if (submitted) {
            if (i === q.answer) cls += " correct";
            else if (i === chosen) cls += " wrong";
          } else if (i === chosen) {
            cls += " selected";
          }
          return (
            <button
              key={i}
              type="button"
              className={cls}
              disabled={submitted}
              onClick={() => setChosen(i)}
            >
              <span className="opt-letter">{String.fromCharCode(65 + i)}</span>
              {opt}
            </button>
          );
        })}
      </div>

      {submitted && (
        <div className={`feedback ${correct ? "fb-correct" : "fb-wrong"}`}>
          <strong>{correct ? "Correct!" : "Incorrect."}</strong> {q.explanation}
        </div>
      )}

      <div className="quiz-actions">
        {!submitted ? (
          <button
            type="button"
            className="btn"
            disabled={chosen === null}
            onClick={handleSubmit}
          >
            Submit answer
          </button>
        ) : (
          <button type="button" className="btn" onClick={handleNext}>
            {idx + 1 < questions.length ? "Next question →" : "See results"}
          </button>
        )}
      </div>
    </div>
  );
}
