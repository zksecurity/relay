package teststore

// PublicationFault is test-only fault injection at the provider boundary.
// Once one new immutable object succeeds, further immutable writes fail until
// disabled, including client retries. Counts include retransmitted bodies.
type PublicationFault struct {
	Armed, Failed bool
	RootWrites    int
	Successful    string
	Attempts      map[string]int
}

func (s *Server) ArmPublicationFault() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicationFault = PublicationFault{Armed: true, Attempts: map[string]int{}}
}
func (s *Server) PublicationFault(disarm bool) PublicationFault {
	s.mu.Lock()
	defer s.mu.Unlock()
	if disarm {
		s.publicationFault.Armed = false
	}
	f := s.publicationFault
	f.Attempts = map[string]int{}
	for k, v := range s.publicationFault.Attempts {
		f.Attempts[k] = v
	}
	return f
}
