package app

import (
	"slices"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

func mapNodeReduce[T any](pods []*corev1.Pod, initFunc func() T, mapFunc func(*corev1.Pod) T, reduceFunc func(T, T) T) T {
	var mu sync.Mutex
	pods = slices.Clone(pods)
	nodes := make(map[string]bool)
	for _, p := range pods {
		nodes[p.Spec.NodeName] = false
	}

	numJobs := min(rootOptions.jobs, len(pods), len(nodes))
	if numJobs == 0 {
		return initFunc()
	}

	pick := func() (*corev1.Pod, bool) {
		mu.Lock()
		defer mu.Unlock()
		for i := len(pods) - 1; i >= 0; i-- {
			p := pods[i]
			if !nodes[p.Spec.NodeName] {
				nodes[p.Spec.NodeName] = true
				pods = slices.Delete(pods, i, i+1)
				return p, true
			}
		}
		return nil, false
	}
	release := func(p *corev1.Pod) {
		mu.Lock()
		defer mu.Unlock()
		if !nodes[p.Spec.NodeName] {
			panic("internal error")
		}
		nodes[p.Spec.NodeName] = false
	}

	var wg sync.WaitGroup
	values := make([]T, numJobs)
	for i := 0; i < numJobs; i++ {
		wg.Go(func() {
			values[i] = initFunc()
			for {
				p, found := pick()
				if !found {
					return
				}
				v := mapFunc(p)
				release(p)

				values[i] = reduceFunc(values[i], v)
			}
		})
	}
	wg.Wait()

	result := values[0]
	for i := 1; i < numJobs; i++ {
		result = reduceFunc(result, values[i])
	}
	return result
}

func compactBy[T any](x []T, cmp func(*T, *T) int, merge func(*T, *T) *T) []T {
	ret := make([]T, 0, len(x))
	if len(x) == 0 {
		return ret
	}

	ret = append(ret, x[0])
	for i := 1; i < len(x); i++ {
		last := &ret[len(ret)-1]
		next := &x[i]

		if cmp(last, next) == 0 {
			ret[len(ret)-1] = *merge(last, next)
		} else {
			ret = append(ret, *next)
		}
	}
	return ret
}

func mergeBy[T any](x, y []T, cmp func(*T, *T) int, merge func(*T, *T) *T) []T {
	var i, j int
	ret := make([]T, 0, len(x)+len(y))

	for i < len(x) && j < len(y) {
		c := cmp(&x[i], &y[j])

		switch {
		case c < 0:
			ret = append(ret, x[i])
			i++

		case c > 0:
			ret = append(ret, y[j])
			j++

		default:
			ret = append(ret, *merge(&x[i], &y[j]))
			i++
			j++
		}
	}

	ret = append(ret, x[i:]...)
	ret = append(ret, y[j:]...)
	return ret
}
