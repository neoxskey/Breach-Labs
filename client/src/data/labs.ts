import { Database, Code, Shield, Lock, Target, Zap, Network, Terminal } from "lucide-react";

export interface Lab {
  id: string;
  title: string;
  difficulty: 'apprentice' | 'practitioner' | 'expert';
  description: string;
  objective: string;
  endpoint: string;
  vulnerability: string;
  hints: string[];
}

export interface Topic {
  id: string;
  name: string;
  icon: any;
  labs: number;
  color: string;
  labList: Lab[];
}

export const topics: Topic[] = [
  { 
    id: 'sqli', 
    name: 'SQL Injection', 
    icon: Database, 
    labs: 4, 
    color: 'text-red-500',
    labList: [
      {
        id: 'sqli-1',
        title: 'SQL injection in WHERE clause',
        difficulty: 'apprentice',
        description: 'SQL injection vulnerability in product category filter.',
        objective: 'Display all products including unreleased ones.',
        endpoint: '/filter?category=',
        vulnerability: 'SQL Injection',
        hints: [
          "The category parameter is used directly in a SQL query",
          "Try breaking out of the quote with a single quote '",
          "Use OR 1=1 to make the condition always true",
          "Comment out the rest of the query with --",
          "Final payload: ' OR 1=1--"
        ]
      },
      {
        id: 'sqli-2',
        title: 'SQL injection login bypass',
        difficulty: 'apprentice',
        description: 'SQL injection in login functionality.',
        objective: 'Login as administrator without password.',
        endpoint: '/login',
        vulnerability: 'SQL Injection',
        hints: [
          "Username and password are used in SQL query",
          "Try username: administrator'--",
          "The -- comments out the password check",
          "Leave password field empty or any value",
          "You'll be logged in as administrator"
        ]
      },
      {
        id: 'sqli-3',
        title: 'UNION attack - column enumeration',
        difficulty: 'practitioner',
        description: 'Determine number of columns using UNION.',
        objective: 'Find the number of columns returned.',
        endpoint: '/filter?category=',
        vulnerability: 'UNION SQLi',
        hints: [
          "Use UNION SELECT to combine results",
          "Start with: ' UNION SELECT NULL--",
          "Add more NULLs until no error",
          "' UNION SELECT NULL,NULL,NULL--",
          "3 columns found when query succeeds"
        ]
      },
      {
        id: 'sqli-4',
        title: 'UNION attack - data extraction',
        difficulty: 'practitioner',
        description: 'Extract usernames and passwords from users table.',
        objective: 'Retrieve all credentials.',
        endpoint: '/filter?category=',
        vulnerability: 'UNION SQLi',
        hints: [
          "First determine column count",
          "Use UNION to select from users table",
          "' UNION SELECT username,password FROM users--",
          "Administrator credentials will appear",
          "Use them to login"
        ]
      }
    ]
  },
  { 
    id: 'xss', 
    name: 'Cross-Site Scripting', 
    icon: Code, 
    labs: 3, 
    color: 'text-orange-500',
    labList: [
      {
        id: 'xss-1',
        title: 'Reflected XSS',
        difficulty: 'apprentice',
        description: 'Simple reflected XSS in search.',
        objective: 'Execute alert() function.',
        endpoint: '/search?query=',
        vulnerability: 'Reflected XSS',
        hints: [
          "Search input is reflected in page",
          "Try: <script>alert(1)</script>",
          "No encoding is applied",
          "Script executes immediately",
          "Lab solved when alert triggers"
        ]
      },
      {
        id: 'xss-2',
        title: 'Stored XSS',
        difficulty: 'apprentice',
        description: 'Stored XSS in comments.',
        objective: 'Store malicious script in comment.',
        endpoint: '/post/comment',
        vulnerability: 'Stored XSS',
        hints: [
          "Comments are stored in database",
          "Submit: <script>alert(document.domain)</script>",
          "Payload stored permanently",
          "Executes for all viewers",
          "Persistent XSS attack"
        ]
      },
      {
        id: 'xss-3',
        title: 'DOM XSS',
        difficulty: 'practitioner',
        description: 'DOM-based XSS in document.write.',
        objective: 'Exploit DOM XSS vulnerability.',
        endpoint: '/search?query=',
        vulnerability: 'DOM XSS',
        hints: [
          "JavaScript uses location.search",
          "Break out of attribute context",
          'Use: "><script>alert(1)</script>',
          "Closes the tag first",
          "Then injects script"
        ]
      }
    ]
  },
  { id: 'csrf', name: 'CSRF', icon: Shield, labs: 2, color: 'text-yellow-500', labList: [] },
  { id: 'auth', name: 'Authentication', icon: Lock, labs: 4, color: 'text-blue-500', labList: [] },
  { id: 'access', name: 'Access Control', icon: Target, labs: 4, color: 'text-purple-500', labList: [] },
  { id: 'business', name: 'Business Logic', icon: Zap, labs: 4, color: 'text-green-500', labList: [] },
  { id: 'ssrf', name: 'SSRF', icon: Network, labs: 3, color: 'text-cyan-500', labList: [] },
  { id: 'xxe', name: 'XXE', icon: Terminal, labs: 3, color: 'text-pink-500', labList: [] }
];

export const achievements = [
  { id: 'first_blood', name: 'First Blood', desc: 'Complete your first lab', icon: '🏆', points: 10, color: 'yellow', requirement: 1 },
  { id: 'sql_master', name: 'SQL Master', desc: 'Complete all SQL Injection labs', icon: '💾', points: 50, color: 'red', requirement: 4 },
  { id: 'xss_ninja', name: 'XSS Ninja', desc: 'Complete all XSS labs', icon: '💻', points: 50, color: 'orange', requirement: 3 },
  { id: 'speed_runner', name: 'Speed Runner', desc: 'Complete a lab in under 2 minutes', icon: '⚡', points: 30, color: 'yellow', requirement: 1 },
  { id: 'completionist', name: 'Completionist', desc: 'Complete all 27 labs', icon: '👑', points: 500, color: 'gold', requirement: 27 }
];

export const ranks = [
  { name: 'Beginner', min: 0, max: 49, icon: '🌱', color: 'text-gray-400' },
  { name: 'Apprentice', min: 50, max: 149, icon: '🎓', color: 'text-green-400' },
  { name: 'Practitioner', min: 150, max: 299, icon: '⚔️', color: 'text-blue-400' },
  { name: 'Expert', min: 300, max: 499, icon: '🔥', color: 'text-orange-400' },
  { name: 'Master', min: 500, max: 999, icon: '👑', color: 'text-purple-400' },
  { name: 'Legend', min: 1000, max: Infinity, icon: '⭐', color: 'text-yellow-400' }
];

export function getRank(points: number) {
  return ranks.find(r => points >= r.min && points <= r.max) || ranks[0];
}
