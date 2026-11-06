export async function requestResponse(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const response = await fetch("/api" + path, {
    ...options,
    headers: {
      ...(options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      detail: "The analysis service could not complete this request.",
    }));
    throw new Error(
      typeof error.detail === "string"
        ? error.detail
        : "Please check the input and try again.",
    );
  }
  return response;
}

export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await requestResponse(path, options);
  return response.status === 204 ? (undefined as T) : response.json();
}
