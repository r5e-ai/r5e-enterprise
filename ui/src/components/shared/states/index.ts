// Barrel export — shared loading / empty / error state primitives.
//
// All three landed together (Wave D) per Constitution Principle VII.
// Use these instead of inline state renderings in pages/components.

export { EmptyState } from "./EmptyState";
export type { EmptyStateAction } from "./EmptyState";
export { ErrorState } from "./ErrorState";
export { PulsingDots } from "./PulsingDots";
export type { PulsingDotsProps, PulsingDotsTone } from "./PulsingDots";
export { Skeleton } from "./Skeleton";
