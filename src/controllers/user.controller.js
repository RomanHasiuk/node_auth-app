import { userService } from '../services/user.service.js';

async function getAll(_req, res) {
  const users = await userService.getAllActive();

  const normalizeUsers = users.map(userService.normalize);

  res.send(normalizeUsers);
}

export const userController = {
  getAll,
};
