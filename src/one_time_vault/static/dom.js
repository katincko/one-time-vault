// @ts-check

/**
 * Element by id, checked to exist and to have the expected type.
 * @template {HTMLElement} T
 * @param {string} id
 * @param {new () => T} type
 * @returns {T}
 */
export function byId(id, type) {
  const el = document.getElementById(id);
  if (!(el instanceof type)) throw new Error(`missing element #${id}`);
  return el;
}
