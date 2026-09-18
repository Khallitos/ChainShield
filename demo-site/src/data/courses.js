export const COURSES = [
  {
    id: "it-security",
    department: "IT",
    level: "Beginner",
    title: "IT Security Basics",
    description: "Learn the fundamentals of cybersecurity, phishing awareness, and safe software practices.",
    icon: "🔒",
    modules: [
      {
        id: "it-sec-1",
        title: "What is a Supply-Chain Attack?",
        type: "video",
        duration: "4 min",
        src: "https://www.youtube.com/embed/SfQkQ8KkG_g",
        description: "A short explainer on how attackers target software supply chains."
      },
      {
        id: "it-sec-2",
        title: "Phishing & Social Engineering",
        type: "slides",
        duration: "6 min",
        slides: [
          { heading: "What is Phishing?", body: "Phishing is a fraudulent attempt to obtain sensitive information by disguising as a trustworthy entity in electronic communication." },
          { heading: "Common Tactics", body: "Spear-phishing, pretexting, baiting, and vishing are the most common social-engineering vectors in corporate environments." },
          { heading: "Red Flags", body: "Urgent requests, mismatched domains, unexpected attachments, and requests for credentials are all warning signs." },
          { heading: "What to Do", body: "Do not click suspicious links. Report to IT security. Verify sender identity through a separate channel." }
        ]
      },
      {
        id: "it-sec-3",
        title: "Security Basics Quiz",
        type: "quiz",
        duration: "5 min",
        questions: [
          {
            q: "What is typosquatting?",
            options: [
              "A typographical error in a document",
              "A malicious package with a name similar to a trusted one",
              "A technique to speed up typing",
              "A type of SQL injection"
            ],
            answer: 1,
            explanation: "Typosquatting publishes packages under names that look like trusted ones to trick developers into installing malicious code."
          },
          {
            q: "Which of the following is a red flag for phishing?",
            options: [
              "An email from your manager's verified address",
              "A calendar invite from a known colleague",
              "An urgent request to click a link and reset your password",
              "A monthly newsletter from IT"
            ],
            answer: 2,
            explanation: "Urgency combined with a link to enter credentials is a classic phishing pattern."
          },
          {
            q: "What should you do if you receive a suspicious email?",
            options: [
              "Forward it to colleagues to warn them",
              "Click the link to verify if it is safe",
              "Delete it immediately without reporting",
              "Report it to your IT/security team"
            ],
            answer: 3,
            explanation: "Always report suspicious emails to your IT or security team so they can investigate and protect the organisation."
          }
        ]
      }
    ]
  },
  {
    id: "finance-basics",
    department: "Finance",
    level: "Intermediate",
    title: "Finance Desk: Month-End Close",
    description: "Step-by-step ledger reconciliation, accruals, and approval workflows for finance staff.",
    icon: "📊",
    modules: [
      {
        id: "fin-1",
        title: "Month-End Close Process",
        type: "slides",
        duration: "8 min",
        slides: [
          { heading: "What is Month-End Close?", body: "Month-end close is the set of procedures a finance team performs at the end of each accounting period to ensure books are accurate and complete." },
          { heading: "Step 1, Reconcile Bank Accounts", body: "Match all bank transactions to entries in the general ledger. Flag any discrepancies immediately for investigation." },
          { heading: "Step 2, Post Accruals", body: "Record expenses incurred but not yet paid (accruals) to ensure the income statement reflects the correct period." },
          { heading: "Step 3, Review and Approve", body: "A senior accountant or controller reviews adjustments before the books are locked for the period." },
          { heading: "Step 4, Generate Reports", body: "Produce P&L, balance sheet, and cash-flow statements for management review." }
        ]
      },
      {
        id: "fin-2",
        title: "Reconciliation Practice",
        type: "task",
        duration: "10 min",
        description: "Download the sample ledger CSV, reconcile the entries, and flag the three errors hidden in the dataset.",
        fileLabel: "Sample Ledger (PDF)",
        fileSrc: "#"
      },
      {
        id: "fin-3",
        title: "Finance Quiz",
        type: "quiz",
        duration: "4 min",
        questions: [
          {
            q: "What is the purpose of an accrual?",
            options: [
              "To delay payment of expenses",
              "To record revenue before it is earned",
              "To match expenses to the period in which they are incurred",
              "To reduce tax liability"
            ],
            answer: 2,
            explanation: "Accruals follow the matching principle: expenses are recorded when incurred, not when cash is paid."
          },
          {
            q: "What does GL stand for in accounting?",
            options: ["Gross Liability", "General Ledger", "Government Listing", "Gross Loss"],
            answer: 1,
            explanation: "GL stands for General Ledger, the master record of all financial transactions."
          }
        ]
      }
    ]
  },
  {
    id: "customer-service",
    department: "Operations",
    level: "Beginner",
    title: "Customer Service Excellence",
    description: "Best practices for handling client queries, complaints, and escalations professionally.",
    icon: "🤝",
    modules: [
      {
        id: "cs-1",
        title: "Handling Difficult Customers",
        type: "video",
        duration: "5 min",
        src: "https://www.youtube.com/embed/sFRKYOCIgXo",
        description: "Practical techniques for de-escalating tense interactions and finding win-win outcomes."
      },
      {
        id: "cs-2",
        title: "Communication Essentials",
        type: "slides",
        duration: "5 min",
        slides: [
          { heading: "Active Listening", body: "Give full attention, avoid interrupting, and reflect back what you heard before responding." },
          { heading: "Empathy Statements", body: "Phrases like 'I understand how frustrating that must be' validate the customer's feelings without admitting fault." },
          { heading: "Resolution Framework", body: "Acknowledge → Apologise → Act. Three steps to resolve any complaint professionally." }
        ]
      },
      {
        id: "cs-3",
        title: "Customer Service Quiz",
        type: "quiz",
        duration: "3 min",
        questions: [
          {
            q: "What does active listening involve?",
            options: [
              "Waiting for your turn to speak",
              "Giving full attention and reflecting back what was heard",
              "Taking detailed notes while ignoring the speaker",
              "Asking multiple questions at once"
            ],
            answer: 1,
            explanation: "Active listening means fully concentrating, understanding, and reflecting the speaker's message before responding."
          },
          {
            q: "What is the correct order of the resolution framework?",
            options: [
              "Act → Apologise → Acknowledge",
              "Apologise → Acknowledge → Act",
              "Acknowledge → Apologise → Act",
              "Acknowledge → Act → Apologise"
            ],
            answer: 2,
            explanation: "Always Acknowledge the issue first, then Apologise, then Act to resolve it."
          }
        ]
      }
    ]
  }
];
