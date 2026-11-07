
import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

// Validate the login input: both values must be ordinary strings.
const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(128).required()
}).unknown(false); // Disallow extra fields (e.g. $where) 

// Only allow searching by instructor name.
const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).required()
}).unknown(false); // Disallow extra fields (e.g. $where)

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { error, value } = loginSchema.validate(req.body, {
      abortEarly: false, //tells Joi to collect all validation errors instead of stopping at the first one.
      convert: false //This disables Joi's automatic type conversion. We want actual strings, not values that Joi might otherwise attempt to convert into strings.
    });

    if (error) {
      return res.status(400).json({ message: 'Invalid login input' });
    }

    const { username, password } = value;

    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.
    const instructor = await Instructor.findOne({ username }).select('+password'); //Only the validated username controls the query. The password is retrieved as a stored hash and compared separately. This eliminates the $ne and $regex password injection mechanism.

    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, instructor.password); //It compares the password provided by the instructor against the stored bcrypt hash. It does not decrypt the hash.

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // ⚠️ VULNERABLE (NoSQL injection): the entire query string is used as the
    // MongoDB filter and full documents (incl. password / apiKey / private
    // contact info) are returned. Examples of what this allows:
    //   ?name=Smith                     -> intended, honest use
    //   ?role[$ne]=instructor           -> operator injection, leaks superadmin
    //   ?username[$regex]=^admin        -> regex enumeration
    //   ?$where=this.password.length>10 -> server-side JavaScript execution

    const { error, value } = searchSchema.validate(req.query, {
      abortEarly: false,
      convert: false
    });

    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters' });
    }

    const { name } = value;

    // Escape regex special characters so the user can search for literal text,
    // but cannot inject their own regular-expression operators.
    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); //This regex finds any character that has special meaning in regex and escapes it with a backslash, so it is treated as a literal character in the search pattern.

    // Build the MongoDB filter ourselves instead of passing req.query directly.
    const filter = {
      name: new RegExp(escapedName, 'i') //We decide what the database query looks like. The user only controls the validated name value.
    };

    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
