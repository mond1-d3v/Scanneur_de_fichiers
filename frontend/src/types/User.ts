export interface User {
  id: string;
  username: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  token: string;
  isAdmin?: boolean;
}
