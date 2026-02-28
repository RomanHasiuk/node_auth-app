import bcrypt from 'bcrypt';
import { db } from '../utils/db.js';

async function getByEmail(email) {
  return db.user.findUnique({
    where: { email },
  });
}

async function create(email, password) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const activationToken = bcrypt.genSaltSync(1);

  return db.user.create({
    data: {
      email,
      password: hashedPassword,
      activationToken,
    },
  });
}

async function getByActivationToken(activationToken) {
  return db.user.findFirst({
    where: { activationToken },
  });
}

async function activate(id) {
  return db.user.update({
    where: { id },
    data: { activationToken: null },
  });
}

function normalize(user) {
  return {
    id: user.id,
    email: user.email,
  };
}

async function getAllActive() {
  return db.user.findMany({
    where: { activationToken: null },
    orderBy: { id: 'asc' },
  });
}

export const userService = {
  getByEmail,
  getByActivationToken,
  create,
  activate,
  normalize,
  getAllActive,
};
