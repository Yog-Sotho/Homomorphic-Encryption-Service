import { writable } from 'svelte/store';

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export const userStore = writable<User | null>(null);
