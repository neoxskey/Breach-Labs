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
  solution?: string;
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
        ],
        solution: "Append ' OR 1=1-- to the category parameter in the URL. For example: /filter?category=Gifts' OR 1=1--. This makes the database query return all items because 1=1 is always true."
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
        ],
        solution: "Enter administrator'-- in the username field and anything in the password field. The -- comments out the rest of the SQL query that would normally check the password, allowing you to log in as the first user found (administrator)."
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
  { 
    id: 'csrf', 
    name: 'CSRF', 
    icon: Shield, 
    labs: 2, 
    color: 'text-yellow-500', 
    labList: [
      {
        id: 'csrf-1',
        title: 'CSRF with no defenses',
        difficulty: 'apprentice',
        description: 'No CSRF protection on email change.',
        objective: 'Change victim email via CSRF.',
        endpoint: '/change-email',
        vulnerability: 'CSRF',
        hints: [
          "Email change has no CSRF token",
          "Create auto-submit form",
          "Set email parameter",
          "Form submits on page load",
          "Email changed without user action"
        ]
      },
      {
        id: 'csrf-2',
        title: 'CSRF method bypass',
        difficulty: 'practitioner',
        description: 'CSRF token only checked on POST.',
        objective: 'Bypass CSRF using GET method.',
        endpoint: '/change-email',
        vulnerability: 'CSRF',
        hints: [
          "POST requests need CSRF token",
          "Try changing to GET method",
          "Token not checked for GET",
          "Use: /change-email?email=attacker@evil.com",
          "Protection bypassed"
        ]
      }
    ]
  },
  { 
    id: 'auth', 
    name: 'Authentication', 
    icon: Lock, 
    labs: 4, 
    color: 'text-blue-500', 
    labList: [
      {
        id: 'auth-1',
        title: 'Username enumeration',
        difficulty: 'apprentice',
        description: 'Different error messages reveal valid usernames.',
        objective: 'Enumerate valid username.',
        endpoint: '/login',
        vulnerability: 'Username Enumeration',
        hints: [
          "Try different usernames",
          "Notice error message differences",
          "Invalid username: 'Invalid username'",
          "Valid username: 'Incorrect password'",
          "Username 'carlos' is valid"
        ]
      },
      {
        id: 'auth-2',
        title: 'Password reset flaw',
        difficulty: 'apprentice',
        description: 'Broken password reset logic.',
        objective: 'Reset Carlos password.',
        endpoint: '/forgot-password',
        vulnerability: 'Broken Reset',
        hints: [
          "Initiate password reset",
          "Intercept the reset request",
          "Notice username parameter",
          "Change username to carlos",
          "Set new password for carlos"
        ]
      },
      {
        id: 'auth-3',
        title: '2FA bypass',
        difficulty: 'apprentice',
        description: '2FA can be bypassed.',
        objective: 'Access account without 2FA.',
        endpoint: '/login',
        vulnerability: '2FA Bypass',
        hints: [
          "Login with valid credentials",
          "2FA page appears",
          "Don't enter 2FA code",
          "Navigate directly to /my-account",
          "Access granted without 2FA"
        ]
      },
      {
        id: 'auth-4',
        title: 'Cookie brute force',
        difficulty: 'practitioner',
        description: 'Weak stay-logged-in cookie.',
        objective: 'Crack the cookie format.',
        endpoint: '/login',
        vulnerability: 'Weak Cookie',
        hints: [
          "Analyze stay-logged-in cookie",
          "Format: base64(username:md5(password))",
          "Generate for common passwords",
          "Base64 encode results",
          "Use cookie to login"
        ]
      }
    ]
  },
  { 
    id: 'access', 
    name: 'Access Control', 
    icon: Target, 
    labs: 4, 
    color: 'text-purple-500', 
    labList: [
      {
        id: 'access-1',
        title: 'Unprotected admin panel',
        difficulty: 'apprentice',
        description: 'Admin panel has no auth.',
        objective: 'Access admin panel.',
        endpoint: '/administrator-panel',
        vulnerability: 'Missing Access Control',
        hints: [
          "Check robots.txt",
          "Guess common admin paths",
          "Navigate to /administrator-panel",
          "No authentication required",
          "Delete carlos user"
        ]
      },
      {
        id: 'access-2',
        title: 'User role parameter',
        difficulty: 'apprentice',
        description: 'Role controlled by request parameter.',
        objective: 'Escalate to admin role.',
        endpoint: '/admin',
        vulnerability: 'Parameter Manipulation',
        hints: [
          "Login with normal user",
          "Notice roleid parameter",
          "Change roleid to 2",
          "Admin access granted",
          "Delete carlos user"
        ]
      },
      {
        id: 'access-3',
        title: 'IDOR vulnerability',
        difficulty: 'apprentice',
        description: 'User ID not validated.',
        objective: 'Access other user data.',
        endpoint: '/my-account?id=',
        vulnerability: 'IDOR',
        hints: [
          "Your account has id parameter",
          "Change id to another user",
          "Try id=carlos",
          "Access carlos data",
          "Retrieve API key"
        ]
      },
      {
        id: 'access-4',
        title: 'Multi-step bypass',
        difficulty: 'practitioner',
        description: 'Missing validation in step 2.',
        objective: 'Escalate privileges.',
        endpoint: '/admin-roles',
        vulnerability: 'Multi-step Flaw',
        hints: [
          "Role change is 2-step",
          "Step 1 validates admin",
          "Step 2 doesn't validate",
          "Skip to step 2",
          "Privilege escalation!"
        ]
      }
    ]
  },
  { 
    id: 'business', 
    name: 'Business Logic', 
    icon: Zap, 
    labs: 4, 
    color: 'text-green-500', 
    labList: [
      {
        id: 'business-1',
        title: 'Client-side price manipulation',
        difficulty: 'apprentice',
        description: 'Price trusted from client.',
        objective: 'Buy expensive item cheaply.',
        endpoint: '/cart',
        vulnerability: 'Client-side Trust',
        hints: [
          "Add item to cart",
          "Intercept the request",
          "Price parameter is sent",
          "Change price to 0.01",
          "Purchase completed!"
        ]
      },
      {
        id: 'business-2',
        title: 'Negative quantity flaw',
        difficulty: 'apprentice',
        description: 'Quantity can be negative.',
        objective: 'Reduce total below zero.',
        endpoint: '/cart',
        vulnerability: 'Logic Flaw',
        hints: [
          "Add expensive item",
          "Add cheap item negative",
          "quantity=-999",
          "Total becomes negative",
          "Checkout successful"
        ]
      },
      {
        id: 'business-3',
        title: 'Email validation bypass',
        difficulty: 'apprentice',
        description: 'Admin domain check after registration.',
        objective: 'Gain admin access.',
        endpoint: '/register',
        vulnerability: 'Validation Bypass',
        hints: [
          "Register normal account",
          "Login successfully",
          "Change email to @dontwannacry.com",
          "Domain check after",
          "Admin panel accessible"
        ]
      },
      {
        id: 'business-4',
        title: 'Parameter injection',
        difficulty: 'practitioner',
        description: 'Hidden parameter accepted.',
        objective: 'Change admin password.',
        endpoint: '/change-password',
        vulnerability: 'Parameter Injection',
        hints: [
          "Change your password",
          "Add username parameter",
          "username=administrator",
          "Endpoint accepts it",
          "Admin password changed!"
        ]
      }
    ]
  },
  { 
    id: 'ssrf', 
    name: 'SSRF', 
    icon: Network, 
    labs: 3, 
    color: 'text-cyan-500', 
    labList: [
      {
        id: 'ssrf-1',
        title: 'SSRF to localhost',
        difficulty: 'apprentice',
        description: 'Access internal services.',
        objective: 'Access admin via localhost.',
        endpoint: '/product/stock',
        vulnerability: 'SSRF',
        hints: [
          "Stock check uses URL",
          "Try http://localhost/admin",
          "Internal services accessible",
          "Admin panel found",
          "Delete carlos user"
        ]
      },
      {
        id: 'ssrf-2',
        title: 'Internal network scan',
        difficulty: 'apprentice',
        description: 'Scan internal network.',
        objective: 'Find admin on internal IP.',
        endpoint: '/product/stock',
        vulnerability: 'SSRF Scan',
        hints: [
          "Try internal IPs",
          "192.168.0.1 to .255",
          "Look for different response",
          "Admin at 192.168.0.68",
          "Access internal admin"
        ]
      },
      {
        id: 'ssrf-3',
        title: 'SSRF filter bypass',
        difficulty: 'practitioner',
        description: 'Bypass localhost blacklist.',
        objective: 'Access blocked localhost.',
        endpoint: '/product/stock',
        vulnerability: 'Filter Bypass',
        hints: [
          "localhost is blocked",
          "Try alternatives",
          "Use 127.1 short form",
          "Or use 127.0.0.1",
          "Blacklist bypassed!"
        ]
      }
    ]
  },
  { 
    id: 'xxe', 
    name: 'XXE', 
    icon: Terminal, 
    labs: 3, 
    color: 'text-pink-500', 
    labList: [
      {
        id: 'xxe-1',
        title: 'XXE file disclosure',
        difficulty: 'apprentice',
        description: 'Read local files via XXE.',
        objective: 'Retrieve /etc/passwd.',
        endpoint: '/product/stock',
        vulnerability: 'XXE',
        hints: [
          "Stock check accepts XML",
          "Add DOCTYPE with entity",
          '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
          "Reference &xxe; in XML",
          "File contents returned"
        ]
      },
      {
        id: 'xxe-2',
        title: 'XXE to SSRF',
        difficulty: 'apprentice',
        description: 'Use XXE for SSRF attack.',
        objective: 'Retrieve EC2 metadata.',
        endpoint: '/product/stock',
        vulnerability: 'XXE to SSRF',
        hints: [
          "XXE can make HTTP requests",
          "Target AWS metadata",
          "http://169.254.169.254/...",
          "Retrieve IAM credentials",
          "Sensitive data exposed"
        ]
      },
      {
        id: 'xxe-3',
        title: 'Blind XXE',
        difficulty: 'practitioner',
        description: 'XXE with no direct output.',
        objective: 'Trigger out-of-band request.',
        endpoint: '/product/stock',
        vulnerability: 'Blind XXE',
        hints: [
          "No direct response",
          "Use out-of-band",
          "External entity to your server",
          "Monitor HTTP/DNS requests",
          "Confirm XXE via logs"
        ]
      }
    ]
  }
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
