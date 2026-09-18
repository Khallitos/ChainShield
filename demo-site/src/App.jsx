import { useState } from "react";
import { COURSES } from "./data/courses.js";
import ModulePlayer from "./components/ModulePlayer.jsx";

/* Supply-chain lab: benign + internal-style deps only. ATK1 typosquat is NOT a dependency here, run `lab-victim-typo-only` to install the attack package fresh. */
import { label as _ledgerLabel } from "training-ledger";
import { label as _internalLabel } from "corp-internal-ledger-api";

const DEPT_FILTERS = ["All", "IT", "Finance", "Operations"];
const LEVEL_FILTERS = ["All Levels", "Beginner", "Intermediate"];

export default function App() {
  const [dept, setDept] = useState("All");
  const [level, setLevel] = useState("All Levels");
  const [activeCourse, setActiveCourse] = useState(null);
  const [activeModule, setActiveModule] = useState(null);
  const [completed, setCompleted] = useState({});

  const courses = COURSES.filter(
    (c) =>
      (dept === "All" || c.department === dept) &&
      (level === "All Levels" || c.level === level)
  );

  function openModule(course, mod) {
    setActiveCourse(course);
    setActiveModule(mod);
  }

  function handleModuleComplete(passed) {
    const key = `${activeCourse.id}__${activeModule.id}`;
    setCompleted((prev) => ({ ...prev, [key]: passed ? "passed" : "attempted" }));
    setActiveModule(null);
  }

  function courseProgress(course) {
    const total = course.modules.length;
    const done = course.modules.filter(
      (m) => completed[`${course.id}__${m.id}`]
    ).length;
    return { done, total, pct: total ? Math.round((done / total) * 100) : 0 };
  }

  if (activeModule) {
    return (
      <div className="page">
        <Nav />
        <ModulePlayer
          module={activeModule}
          onComplete={handleModuleComplete}
          onBack={() => setActiveModule(null)}
        />
      </div>
    );
  }

  if (activeCourse) {
    const prog = courseProgress(activeCourse);
    return (
      <div className="page">
        <Nav />
        <button type="button" className="back-btn" onClick={() => setActiveCourse(null)}>
          ← All courses
        </button>
        <div className="course-hero">
          <span className="course-icon">{activeCourse.icon}</span>
          <div>
            <p className="eyebrow">{activeCourse.department} · {activeCourse.level}</p>
            <h1>{activeCourse.title}</h1>
            <p className="lede">{activeCourse.description}</p>
          </div>
        </div>

        <div className="prog-row">
          <div className="prog-bar-wrap">
            <div className="prog-bar" style={{ width: `${prog.pct}%` }} />
          </div>
          <span className="prog-label">{prog.done} / {prog.total} complete</span>
        </div>

        <div className="module-list">
          {activeCourse.modules.map((mod, i) => {
            const key = `${activeCourse.id}__${mod.id}`;
            const status = completed[key];
            return (
              <div key={mod.id} className={`module-row ${status ? "done" : ""}`}>
                <div className="module-meta">
                  <span className="module-num">{i + 1}</span>
                  <div>
                    <p className="module-title">{mod.title}</p>
                    <p className="module-info">
                      <span className={`type-chip ${mod.type}`}>{mod.type}</span>
                      {mod.duration}
                    </p>
                  </div>
                </div>
                <div className="module-actions">
                  {status === "passed" && <span className="check-badge">✓ Passed</span>}
                  {status === "attempted" && <span className="try-badge">Attempted</span>}
                  <button
                    type="button"
                    className="btn"
                    onClick={() => openModule(activeCourse, mod)}
                  >
                    {status ? "Review" : "Start"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <Nav />

      <header className="hero">
        <div>
          <p className="eyebrow">Employee Training Portal</p>
          <h1>Learn at your own pace</h1>
          <p className="lede">
            Courses organised by department and skill level. Complete lessons, watch videos,
            and pass quizzes to earn your module certificates.
          </p>
        </div>
        <div className="hero-stats">
          <div className="stat">
            <strong>{COURSES.length}</strong>
            <span>Courses</span>
          </div>
          <div className="stat">
            <strong>{COURSES.reduce((a, c) => a + c.modules.length, 0)}</strong>
            <span>Modules</span>
          </div>
        </div>
      </header>

      <div className="filters">
        <div className="filter-group">
          {DEPT_FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              className={`filter-btn ${dept === f ? "active" : ""}`}
              onClick={() => setDept(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="filter-group">
          {LEVEL_FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              className={`filter-btn ${level === f ? "active" : ""}`}
              onClick={() => setLevel(f)}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="course-grid">
        {courses.map((course) => {
          const prog = courseProgress(course);
          return (
            <article key={course.id} className="course-card">
              <div className="course-card-top">
                <span className="course-icon">{course.icon}</span>
                <div className="course-pills">
                  <span className="dept-pill">{course.department}</span>
                  <span className="level-pill">{course.level}</span>
                </div>
              </div>
              <h2>{course.title}</h2>
              <p>{course.description}</p>
              <p className="mod-count">{course.modules.length} modules</p>
              {prog.done > 0 && (
                <div className="prog-bar-wrap small">
                  <div className="prog-bar" style={{ width: `${prog.pct}%` }} />
                </div>
              )}
              <button
                type="button"
                className="btn"
                onClick={() => setActiveCourse(course)}
              >
                {prog.done > 0 ? `Continue (${prog.pct}%)` : "Start course"}
              </button>
            </article>
          );
        })}
      </div>
    </div>
  );
}

function Nav() {
  return (
    <nav className="topnav">
      <span className="nav-brand">🏢 TrainHub</span>
      <div className="nav-links">
        <a href="#">My courses</a>
        <a href="#">Progress</a>
        <span className="nav-avatar">JD</span>
      </div>
    </nav>
  );
}
